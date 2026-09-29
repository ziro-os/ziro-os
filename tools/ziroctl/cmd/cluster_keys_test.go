package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// withTempCluster points clusterDir at a temp dir and resets the keyring.
func withTempCluster(t *testing.T) string {
	t.Helper()
	old := clusterDir
	clusterDir = t.TempDir()
	keyring.mu.Lock()
	oldKeys, oldPrimary := keyring.keys, keyring.primary
	keyring.keys, keyring.primary = nil, ""
	keyring.mu.Unlock()
	t.Cleanup(func() {
		clusterDir = old
		keyring.mu.Lock()
		keyring.keys, keyring.primary = oldKeys, oldPrimary
		keyring.mu.Unlock()
	})
	return clusterDir
}

func sealedState(t *testing.T) *ClusterState {
	st := &ClusterState{NodeTokens: map[string]string{}, History: map[string][]ClusteredApp{},
		Secrets: map[string]map[string]string{"db": {"PASS": "hunter2"}}, CAKey: "-----CA KEY-----"}
	key := newDEK()
	setKeyring(key)
	st.DEKID = dekFingerprint(key)
	return st
}

func TestSealBlob(t *testing.T) {
	key := newDEK()
	id := dekFingerprint(key)
	b, err := sealBlob(key, id, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := openBlob(key, id, b); err != nil || string(out) != "secret" {
		t.Fatalf("round trip: %q %v", out, err)
	}
	if _, err := openBlob(key, "other-id", b); err == nil {
		t.Fatal("the key ID must be authenticated")
	}
	b[len(b)-1] ^= 1
	if _, err := openBlob(key, id, b); err == nil {
		t.Fatal("tampering not detected")
	}
	if _, err := openBlob(key, id, []byte{1, 2}); err == nil {
		t.Fatal("truncated blob accepted")
	}
}

func TestSealedPayload(t *testing.T) {
	dir := withTempCluster(t)
	st := sealedState(t)
	b, err := encodePayload(st)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("hunter2")) || bytes.Contains(b, []byte("CA KEY")) {
		t.Fatal("plaintext secret in the sealed payload")
	}
	got, err := decodePayload(b)
	if err != nil || got.Secrets["db"]["PASS"] != "hunter2" || got.CAKey != st.CAKey || got.sealed != nil {
		t.Fatalf("decode with key: %+v %v", got.Secrets, err)
	}

	// Persisted sealed: no plaintext file survives, nothing readable on disk.
	_ = os.WriteFile(filepath.Join(dir, "secrets.json"), []byte(`{"old":{"K":"leak"}}`), 0600)
	_ = os.WriteFile(filepath.Join(dir, "ca.key"), []byte("old"), 0600)
	if err := persistPayload(dir, b); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"secrets.json", "ca.key"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			t.Fatalf("%s left on disk after sealing", f)
		}
	}
	for _, f := range []string{"state.json", "sealed.bin"} {
		if data, _ := os.ReadFile(filepath.Join(dir, f)); bytes.Contains(data, []byte("hunter2")) || len(data) == 0 {
			t.Fatalf("%s: missing or plaintext", f)
		}
	}
	if fs, err := loadStateFile(); err != nil || fs.Secrets["db"]["PASS"] != "hunter2" {
		t.Fatalf("file state round trip: %v", err)
	}

	// Without the key: locked, passed through unchanged, never re-encrypted or altered.
	keyring.mu.Lock()
	keyring.keys, keyring.primary = nil, ""
	keyring.mu.Unlock()
	locked, err := decodePayload(b)
	if err != nil || locked.sealed == nil || len(locked.Secrets) != 0 {
		t.Fatalf("locked decode: %v", err)
	}
	b2, err := encodePayload(cloneState(locked))
	var p1, p2 raftPayload
	_ = json.Unmarshal(b, &p1)
	_ = json.Unmarshal(b2, &p2)
	if err != nil || !bytes.Equal(p1.Sealed, p2.Sealed) {
		t.Fatalf("locked passthrough must keep the sealed blob byte for byte: %v", err)
	}
	locked.Secrets["new"] = map[string]string{"K": "v"}
	if _, err := encodePayload(locked); !errors.Is(err, errSecretsLocked) {
		t.Fatalf("changing secrets while locked: %v", err)
	}
	if _, err := encodePlainPayload(locked); !errors.Is(err, errSecretsLocked) {
		t.Fatal("a locked state must not be served as plaintext")
	}
	if !bytes.Equal(hardKey(cloneState(st)), hardKey(st)) {
		t.Fatal("hardKey must be deterministic")
	}
}

func TestSealGatingAndFileProvider(t *testing.T) {
	withTempCluster(t)
	st := &ClusterState{Nodes: []ClusterNode{{ID: "master-1", Role: "master", Caps: nodeCaps}, {ID: "master-2", Role: "master"}}}
	if err := maybeSealSecrets(st); err != nil || st.DEKID != "" {
		t.Fatalf("sealed while a master runs an older version: %v", err)
	}
	st.Nodes[1].Caps = nodeCaps
	if err := maybeSealSecrets(st); err != nil || st.DEKID == "" {
		t.Fatalf("not sealed: %v", err)
	}
	key, err := loadStoredDEK()
	if err != nil || dekFingerprint(key) != st.DEKID {
		t.Fatalf("stored key: %v", err)
	}
	if fi, _ := os.Stat(dekPath()); fi.Mode().Perm() != 0600 {
		t.Fatalf("dek.bin mode %v", fi.Mode())
	}
}

func TestCommandProvider(t *testing.T) {
	dir := withTempCluster(t)
	// A toy "KMS": wrap reverses the base64 text, unwrap reverses it back.
	wrap := filepath.Join(dir, "wrap")
	unwrap := filepath.Join(dir, "unwrap")
	script := "#!/bin/sh\nrev\n"
	_ = os.WriteFile(wrap, []byte(script), 0700)
	_ = os.WriteFile(unwrap, []byte(script), 0700)
	cfg, _ := json.Marshal(keyProviderConfig{Provider: "command", Wrap: wrap, Unwrap: unwrap})
	_ = os.WriteFile(keysConfigPath(), cfg, 0600)

	key := newDEK()
	if err := storeDEK(key); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(dekPath()); bytes.Contains(raw, key) {
		t.Fatal("command provider stored the raw key")
	}
	if got, err := loadStoredDEK(); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("unwrap: %v", err)
	}
	// An unwrap that returns a different key is refused.
	_ = os.WriteFile(unwrap, []byte("#!/bin/sh\necho AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"), 0700)
	if _, err := loadStoredDEK(); err == nil || !strings.Contains(err.Error(), "wrong cluster data key") {
		t.Fatalf("wrong key accepted: %v", err)
	}
	if err := validateKeyConfig(keyProviderConfig{Provider: "command", Wrap: "rev", Unwrap: unwrap}); err == nil {
		t.Fatal("relative command accepted")
	}
}

func TestCompactAfterSeal(t *testing.T) {
	dir := withTempCluster(t)
	_ = os.MkdirAll(filepath.Join(dir, "raft"), 0700)
	_, trans := raft.NewInmemTransport("solo")
	store := raft.NewInmemStore()
	imported := &ClusterState{NodeTokens: map[string]string{}, History: map[string][]ClusteredApp{},
		Secrets: map[string]map[string]string{"db": {"PASS": "plain-before-seal"}}, CAKey: "CAKEY"}
	rs, err := newRaftStore("solo", dir, trans, store, store, raft.NewInmemSnapshotStore(), true,
		func() (*ClusterState, error) { return cloneState(imported), nil })
	if err != nil {
		t.Fatal(err)
	}
	defer rs.r.Shutdown()
	waitFor(t, "leader", rs.isLeader)
	for i := 0; i < 3; i++ { // pre-seal history with plaintext secrets
		_ = rs.mutate(func(st *ClusterState) error { st.JoinToken = fmt.Sprint("t", i); return nil })
	}
	if err := rs.mutate(func(st *ClusterState) error {
		st.Nodes = []ClusterNode{{ID: "solo", Role: "master", Caps: nodeCaps}}
		return maybeSealSecrets(st)
	}); err != nil {
		t.Fatal(err)
	}
	_, sealedAt := rs.fsm.latest()
	if err := rs.compactAfterSeal(); err != nil {
		t.Fatal(err)
	}
	first, _ := store.FirstIndex()
	if first != 0 && first <= sealedAt-1 {
		t.Fatalf("pre-seal entries still in the log: first index %d, sealed at %d", first, sealedAt)
	}
	for idx := first; idx != 0 && idx <= sealedAt; idx++ {
		var l raft.Log
		if store.GetLog(idx, &l) == nil && bytes.Contains(l.Data, []byte("plain-before-seal")) {
			t.Fatalf("log entry %d still holds a plaintext secret", idx)
		}
	}
	if err := rs.compactAfterSeal(); err != nil || !fileExists(filepath.Join(dir, "raft", "sealed-compacted")) {
		t.Fatal("compaction must run once and leave its marker")
	}
}

func TestDEKRotation(t *testing.T) {
	withTempCluster(t)
	st := &ClusterState{NodeTokens: map[string]string{}, History: map[string][]ClusteredApp{},
		Secrets: map[string]map[string]string{"db": {"PASS": "rotate-me"}}, CAKey: "CAKEY",
		Nodes: []ClusterNode{{ID: "m1", Role: "master", Caps: nodeCaps}, {ID: "m2", Role: "master", Caps: nodeCaps}}}
	if err := maybeSealSecrets(st); err != nil {
		t.Fatal(err)
	}
	oldID := st.DEKID
	oldPayload, err := encodePayload(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := maybeRotateDEK(st); err != nil || st.NextDEKID != "" {
		t.Fatal("no rotation without a request")
	}
	st.DEKRotateRequested = time.Now()
	if err := maybeRotateDEK(st); err != nil || st.NextDEKID == "" || st.NextDEKID == oldID {
		t.Fatalf("next key: %v %q", err, st.NextDEKID)
	}
	next := st.NextDEKID
	if ids := storedKeyIDs(); len(ids) != 2 || ids[1] != next {
		t.Fatalf("stored keys: %v", ids)
	}
	// Every master's background loop promotes/retires keys every few seconds: during a rotation it
	// must keep the pending next key (a regression here stalled rotation in the QEMU HA test).
	promoteRotatedKey(st.DEKID, st.NextDEKID)
	if keyByID(next) == nil || keyByID(oldID) == nil {
		t.Fatal("promotion during a rotation dropped a key still in use")
	}
	// The leader's loop can run before the next key is committed (it sees no NextDEKID yet):
	// the key must survive because it is stored in dek-next.bin.
	promoteRotatedKey(st.DEKID, "")
	if keyByID(next) == nil {
		t.Fatal("promotion dropped the uncommitted next key (rotation would stall)")
	}
	st.Nodes[0].Keys = storedKeyIDs() // m1 holds it, m2 does not yet
	if _ = maybeRotateDEK(st); st.DEKID != oldID {
		t.Fatal("switched before every master held the next key")
	}
	st.Nodes[1].Keys = []string{oldID, next}
	if err := maybeRotateDEK(st); err != nil || st.DEKID != next || st.NextDEKID != "" {
		t.Fatalf("switch: %v %q", err, st.DEKID)
	}
	b, err := encodePayload(st)
	if err != nil {
		t.Fatal(err)
	}
	promoteRotatedKey(st.DEKID, st.NextDEKID)
	if ids := storedKeyIDs(); len(ids) != 1 || ids[0] != next || keyringSize() != 1 {
		t.Fatalf("after promotion: stored %v, keyring %d", ids, keyringSize())
	}
	got, err := decodePayload(b)
	if err != nil || got.sealed != nil || got.Secrets["db"]["PASS"] != "rotate-me" || got.CAKey != "CAKEY" {
		t.Fatalf("re-sealed state: %v", err)
	}
	// The retired key is gone: an entry sealed with it cannot be opened any more.
	old, err := decodePayload(oldPayload)
	if err != nil || old.sealed == nil {
		t.Fatalf("old entry must stay sealed: %v", err)
	}
}
