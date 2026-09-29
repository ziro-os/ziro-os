package cmd

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/spf13/cobra"
)

// Secrets at rest. One random cluster data key (DEK, AES-256) seals the cluster secrets and the
// CA key (AES-GCM) in the Raft log, its snapshots and every master's files. Each master keeps
// its own copy of the DEK wrapped by a key provider:
//
//   file     the DEK in a 0600 file (default; protects backups and copied Raft data, not a
//            compromised host)
//   tpm      sealed to this host's TPM 2.0 (bare metal, cloud vTPM): useless on any other machine
//   command  wrapped by an operator command (AWS/GCP KMS, Vault, an HSM through their own CLIs)
//
// A master without the DEK fetches it from another master over mutual TLS and wraps it with its
// own provider; the first leader after an upgrade creates it and seals the existing secrets.

const dekSize = 32

func keysConfigPath() string { return filepath.Join(clusterDir, "keys.json") }
func dekPath() string        { return filepath.Join(clusterDir, "dek.bin") }
func dekNextPath() string    { return filepath.Join(clusterDir, "dek-next.bin") } // during a rotation

var tpmDevice = "/dev/tpmrm0"

// keyProviderConfig selects this master's provider. Command providers are executables (no
// shell): wrap reads the DEK (base64) on stdin and prints the wrapped blob; unwrap reads that
// blob on stdin and prints the DEK (base64).
type keyProviderConfig struct {
	Provider string `json:"provider"`
	Wrap     string `json:"wrap,omitempty"`
	Unwrap   string `json:"unwrap,omitempty"`
}

type wrappedDEK struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Blob     []byte `json:"blob"`
}

// nodeCaps: features this ziroctl supports, reported in heartbeats. The leader seals secrets only
// once every master reports capSealedSecrets, so a master still on an older version (which would
// read sealed state as "no secrets") never sees a sealed entry.
const capSealedSecrets = "sealed-secrets"

var nodeCaps = []string{capSealedSecrets}

func hasCap(n *ClusterNode, c string) bool {
	for _, x := range n.Caps {
		if x == c {
			return true
		}
	}
	return false
}

// maybeSealSecrets gives an unsealed cluster its data key (creating and storing it on this
// leader) once every master can read sealed state.
func maybeSealSecrets(st *ClusterState) error {
	if st.DEKID != "" {
		return nil
	}
	for i := range st.Nodes {
		if st.Nodes[i].Role == "master" && !hasCap(&st.Nodes[i], capSealedSecrets) {
			return nil // a master on an older version: wait
		}
	}
	key, _ := currentKey()
	if key == nil {
		key = newDEK()
		if err := storeDEK(key); err != nil {
			return fmt.Errorf("store the cluster data key: %w", err)
		}
		setKeyring(key)
	}
	st.DEKID = dekFingerprint(key)
	fmt.Printf("[cluster] sealing cluster secrets with data key %s\n", st.DEKID)
	return nil
}

// maybeRotateDEK advances a requested data key rotation (leader tick). A new key is created and
// distributed first; the secrets are re-sealed with it only once every master holds it, so no
// master is ever left unable to open them.
func maybeRotateDEK(st *ClusterState) error {
	if st.DEKID == "" {
		return nil
	}
	if st.NextDEKID == "" {
		if st.DEKRotateRequested.IsZero() {
			return nil
		}
		key := newDEK()
		if err := storeWrapped(dekNextPath(), key); err != nil {
			return fmt.Errorf("store the next data key: %w", err)
		}
		st.NextDEKID, st.DEKRotateRequested = addKey(key), time.Time{}
		fmt.Printf("[cluster] data key rotation: next key %s, waiting for every master to hold it\n", st.NextDEKID)
		return nil
	}
	if keyByID(st.NextDEKID) == nil {
		return nil // this leader has not fetched it yet
	}
	for i := range st.Nodes {
		n := &st.Nodes[i]
		if n.Role == "master" && !containsString(n.Keys, st.NextDEKID) {
			return nil
		}
	}
	st.DEKID, st.NextDEKID = st.NextDEKID, ""
	fmt.Printf("[cluster] data key rotated: secrets re-sealed with %s\n", st.DEKID)
	return nil
}

// promoteRotatedKey makes this master's stored next key its current one once the cluster
// switched to it, and forgets retired keys. Retirement follows the key files, never the (possibly
// not yet committed) state: a key still stored in dek.bin or dek-next.bin stays in memory. The
// leader creates the next key before committing it, and dropping it in that window stalled
// rotation in the QEMU HA test.
func promoteRotatedKey(id, next string) {
	var w wrappedDEK
	if b, err := os.ReadFile(dekNextPath()); err == nil && json.Unmarshal(b, &w) == nil && w.ID == id {
		if err := os.Rename(dekNextPath(), dekPath()); err != nil {
			fmt.Printf("[cluster] promote data key: %v\n", err)
			return
		}
	}
	if keyByID(id) == nil {
		return
	}
	keep := append(storedKeyIDs(), id, next)
	keyring.mu.Lock()
	defer keyring.mu.Unlock()
	for k := range keyring.keys {
		if !containsString(keep, k) {
			delete(keyring.keys, k)
		}
	}
	keyring.primary = id
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func dekFingerprint(key []byte) string {
	sum := sha256.Sum256(append([]byte("ziro-dek:"), key...))
	return hex.EncodeToString(sum[:8])
}

// ---- keyring (this process's copy of the DEK) ----

// keyring holds this process's data keys by ID: the current one and, during a rotation, the next.
var keyring struct {
	mu      sync.RWMutex
	keys    map[string][]byte
	primary string
}

// setKeyring makes key the current key (and keeps any other key for a rotation in progress).
func setKeyring(key []byte) {
	id := addKey(key)
	keyring.mu.Lock()
	keyring.primary = id
	keyring.mu.Unlock()
}

func addKey(key []byte) string {
	id := dekFingerprint(key)
	keyring.mu.Lock()
	if keyring.keys == nil {
		keyring.keys = map[string][]byte{}
	}
	keyring.keys[id] = key
	keyring.mu.Unlock()
	return id
}

func currentKey() ([]byte, string) {
	keyring.mu.RLock()
	defer keyring.mu.RUnlock()
	return keyring.keys[keyring.primary], keyring.primary
}

func keyByID(id string) []byte {
	keyring.mu.RLock()
	defer keyring.mu.RUnlock()
	return keyring.keys[id]
}

func keyringSize() int {
	keyring.mu.RLock()
	defer keyring.mu.RUnlock()
	return len(keyring.keys)
}

func newDEK() []byte {
	k := make([]byte, dekSize)
	if _, err := rand.Read(k); err != nil {
		panic(err) // crypto/rand failure
	}
	return k
}

// ---- sealing ----

var errSecretsLocked = errors.New("cluster secrets are sealed with a data key this master does not have yet")

// sealBlob encrypts plaintext with the DEK; the key ID is authenticated, so a blob can never be
// opened (or swapped in) under another key.
func sealBlob(key []byte, id string, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, []byte("ziro-secrets:"+id)), nil
}

func openBlob(key []byte, id string, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("sealed secrets are truncated")
	}
	out, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], []byte("ziro-secrets:"+id))
	if err != nil {
		return nil, errors.New("sealed secrets failed authentication (wrong key or tampered)")
	}
	return out, nil
}

// ---- providers ----

func loadKeyConfig() keyProviderConfig {
	c := keyProviderConfig{Provider: "file"}
	if b, err := os.ReadFile(keysConfigPath()); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	return c
}

func validateKeyConfig(c keyProviderConfig) error {
	switch c.Provider {
	case "file", "tpm":
		return nil
	case "command":
		for _, p := range []string{c.Wrap, c.Unwrap} {
			if !filepath.IsAbs(p) {
				return fmt.Errorf("command provider needs absolute --wrap and --unwrap executables")
			}
			if fi, err := os.Stat(p); err != nil || fi.Mode()&0111 == 0 {
				return fmt.Errorf("%s is not an executable", p)
			}
		}
		return nil
	}
	return fmt.Errorf("unknown key provider %q (file, tpm, command)", c.Provider)
}

func runKeyCommand(path string, stdin []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, path)
	c.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		return nil, fmt.Errorf("%s: %v: %s", path, err, strings.TrimSpace(errb.String()))
	}
	return bytes.TrimSpace(out.Bytes()), nil
}

func wrapDEK(c keyProviderConfig, key []byte) ([]byte, error) {
	switch c.Provider {
	case "file":
		return key, nil
	case "command":
		return runKeyCommand(c.Wrap, []byte(base64.StdEncoding.EncodeToString(key)))
	case "tpm":
		tpm, err := linuxtpm.Open(tpmDevice)
		if err != nil {
			return nil, fmt.Errorf("TPM %s: %w", tpmDevice, err)
		}
		defer tpm.Close()
		return tpmSeal(tpm, key)
	}
	return nil, fmt.Errorf("unknown key provider %q", c.Provider)
}

func unwrapDEK(w wrappedDEK, c keyProviderConfig) ([]byte, error) {
	switch w.Provider {
	case "file":
		return w.Blob, nil
	case "command":
		out, err := runKeyCommand(c.Unwrap, w.Blob)
		if err != nil {
			return nil, err
		}
		return base64.StdEncoding.DecodeString(string(out))
	case "tpm":
		tpm, err := linuxtpm.Open(tpmDevice)
		if err != nil {
			return nil, fmt.Errorf("TPM %s: %w", tpmDevice, err)
		}
		defer tpm.Close()
		return tpmUnseal(tpm, w.Blob)
	}
	return nil, fmt.Errorf("unknown key provider %q", w.Provider)
}

// storeDEK wraps key with this master's provider and checks the round trip before replacing
// the stored copy.
func storeDEK(key []byte) error { return storeWrapped(dekPath(), key) }

func storeWrapped(path string, key []byte) error {
	c := loadKeyConfig()
	if err := validateKeyConfig(c); err != nil {
		return err
	}
	blob, err := wrapDEK(c, key)
	if err != nil {
		return err
	}
	w := wrappedDEK{ID: dekFingerprint(key), Provider: c.Provider, Blob: blob}
	back, err := unwrapDEK(w, c)
	if err != nil || !bytes.Equal(back, key) {
		return fmt.Errorf("%s provider: the wrapped key does not unwrap to the same key (%v)", c.Provider, err)
	}
	b, err := json.Marshal(w)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(clusterDir, 0700); err != nil {
		return err
	}
	return writeFileAtomic(path, b, 0600)
}

// loadStoredDEK unwraps this master's copy of the DEK (nil, nil when it has none yet).
func loadStoredDEK() ([]byte, error) { return loadWrapped(dekPath()) }

// storedKeyIDs lists the data keys this master holds (current and next) without unwrapping
// them; agents report it so the leader knows when every master can open a new key.
func storedKeyIDs() []string {
	var ids []string
	for _, p := range []string{dekPath(), dekNextPath()} {
		var w wrappedDEK
		if b, err := os.ReadFile(p); err == nil && json.Unmarshal(b, &w) == nil && w.ID != "" {
			ids = append(ids, w.ID)
		}
	}
	return ids
}

func loadWrapped(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var w wrappedDEK
	if err := json.Unmarshal(b, &w); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	key, err := unwrapDEK(w, loadKeyConfig())
	if err != nil {
		return nil, fmt.Errorf("unwrap the cluster data key (%s provider): %w", w.Provider, err)
	}
	if len(key) != dekSize || dekFingerprint(key) != w.ID {
		return nil, fmt.Errorf("the %s provider returned the wrong cluster data key", w.Provider)
	}
	return key, nil
}

// ---- TPM 2.0 ----

// The sealed object lives under the owner-hierarchy ECC SRK, which the TPM derives the same way
// every time. Sessions are salted to the SRK and encrypt the sensitive parameter, so the DEK
// never crosses the TPM bus in the clear.
// ponytail: not bound to PCRs (kernel/OS upgrades would lock the key); add a PCR policy for
// measured-boot deployments.
func tpmSRK(tpm transport.TPM) (*tpm2.CreatePrimaryResponse, *tpm2.TPMTPublic, error) {
	srk, err := tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}.Execute(tpm)
	if err != nil {
		return nil, nil, fmt.Errorf("create SRK: %w", err)
	}
	pub, err := srk.OutPublic.Contents()
	if err != nil {
		_, _ = tpm2.FlushContext{FlushHandle: srk.ObjectHandle}.Execute(tpm)
		return nil, nil, err
	}
	return srk, pub, nil
}

type tpmBlob struct {
	Public  []byte `json:"public"`
	Private []byte `json:"private"`
}

func tpmSeal(tpm transport.TPM, secret []byte) ([]byte, error) {
	srk, pub, err := tpmSRK(tpm)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext{FlushHandle: srk.ObjectHandle}.Execute(tpm)
	rsp, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: srk.ObjectHandle, Name: srk.Name,
			Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.Salted(srk.ObjectHandle, *pub))},
		InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
			Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: secret}),
		}},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type: tpm2.TPMAlgKeyedHash, NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true, UserWithAuth: true, NoDA: true},
		}),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	return json.Marshal(tpmBlob{Public: tpm2.Marshal(rsp.OutPublic), Private: tpm2.Marshal(rsp.OutPrivate)})
}

func tpmUnseal(tpm transport.TPM, blob []byte) ([]byte, error) {
	var b tpmBlob
	if err := json.Unmarshal(blob, &b); err != nil {
		return nil, err
	}
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](b.Public)
	if err != nil {
		return nil, err
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](b.Private)
	if err != nil {
		return nil, err
	}
	srk, srkPub, err := tpmSRK(tpm)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext{FlushHandle: srk.ObjectHandle}.Execute(tpm)
	obj, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{Handle: srk.ObjectHandle, Name: srk.Name},
		InPrivate:    *priv, InPublic: *pub,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("load sealed key (another TPM?): %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: obj.ObjectHandle}.Execute(tpm)
	out, err := tpm2.Unseal{ItemHandle: tpm2.AuthHandle{Handle: obj.ObjectHandle, Name: obj.Name,
		Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptOut), tpm2.Salted(srk.ObjectHandle, *srkPub))},
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("unseal: %w", err)
	}
	return out.OutData.Buffer, nil
}

// ---- CLI ----

var clusterKeysCmd = &cobra.Command{Use: "keys", Short: "Encryption of cluster secrets at rest (per-master key provider)"}

type keysStatusView struct {
	Provider   string   `json:"provider"`
	LocalKey   string   `json:"local_key,omitempty"`   // fingerprint of this master's DEK copy
	ClusterKey string   `json:"cluster_key,omitempty"` // fingerprint the replicated secrets are sealed with
	Sealed     bool     `json:"sealed"`
	NextKey    string   `json:"next_key,omitempty"` // rotation in progress
	Waiting    []string `json:"waiting_for,omitempty"`
	Error      string   `json:"error,omitempty"`
}

var clusterKeysStatusCmd = &cobra.Command{
	Use: "status", Short: "Show this master's key provider and whether it holds the cluster data key",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		v := keysStatusView{Provider: loadKeyConfig().Provider}
		if key, err := loadStoredDEK(); err != nil {
			v.Error = err.Error()
		} else if key != nil {
			v.LocalKey = dekFingerprint(key)
		}
		if st, err := readState(); err == nil {
			v.ClusterKey, v.Sealed, v.NextKey = st.DEKID, st.DEKID != "", st.NextDEKID
			for _, n := range st.Nodes {
				if v.NextKey != "" && n.Role == "master" && !containsString(n.Keys, v.NextKey) {
					v.Waiting = append(v.Waiting, n.ID)
				}
			}
		}
		return printResult(v, func() {
			fmt.Printf("Provider:      %s\n", v.Provider)
			fmt.Printf("Secrets:       %s\n", map[bool]string{true: "sealed (AES-256-GCM) with key " + v.ClusterKey, false: "not sealed yet (the leader seals them on start)"}[v.Sealed])
			switch {
			case v.Error != "":
				fmt.Printf("This master:   ✗ %s\n", v.Error)
			case v.LocalKey == "":
				fmt.Println("This master:   no copy yet (fetched from another master automatically)")
			case v.Sealed && v.LocalKey != v.ClusterKey:
				fmt.Printf("This master:   ✗ holds key %s, the cluster uses %s\n", v.LocalKey, v.ClusterKey)
			default:
				fmt.Printf("This master:   ✓ holds key %s\n", v.LocalKey)
			}
			if v.NextKey != "" {
				fmt.Printf("Rotation:      to %s, waiting for %v\n", v.NextKey, v.Waiting)
			}
		})
	},
}

var keysWrap, keysUnwrap string

var clusterKeysProviderCmd = &cobra.Command{
	Use:   "provider file|tpm|command",
	Short: "Re-wrap this master's copy of the cluster data key with another provider",
	Long: `Each master chooses its own provider:

  ziroctl cluster keys provider tpm
  ziroctl cluster keys provider command --wrap /usr/local/bin/kms-wrap --unwrap /usr/local/bin/kms-unwrap

A command provider is two executables (no shell): wrap reads the key (base64) on stdin and prints
the wrapped blob; unwrap reads that blob on stdin and prints the key (base64). They can call any
KMS, Vault or HSM CLI. The new wrapping is verified before the old one is replaced.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		next := keyProviderConfig{Provider: args[0], Wrap: keysWrap, Unwrap: keysUnwrap}
		if err := validateKeyConfig(next); err != nil {
			return err
		}
		key, err := loadStoredDEK()
		if err != nil {
			return err
		}
		prev, hadPrev := os.ReadFile(keysConfigPath())
		b, _ := json.MarshalIndent(next, "", "  ")
		if err := writeFileAtomic(keysConfigPath(), b, 0600); err != nil {
			return err
		}
		if key != nil {
			if err := storeDEK(key); err != nil { // restore the previous provider on failure
				if hadPrev == nil {
					_ = writeFileAtomic(keysConfigPath(), prev, 0600)
				} else {
					_ = os.Remove(keysConfigPath())
				}
				return err
			}
		}
		fmt.Printf("✓ key provider: %s", next.Provider)
		if key != nil {
			fmt.Printf(" (cluster data key %s re-wrapped)", dekFingerprint(key))
		}
		fmt.Println()
		return nil
	},
}

var clusterKeysRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Replace the cluster data key and re-seal every secret with the new one",
	Long: `The leader creates a new data key, every master fetches it (mutual TLS) and wraps it with its
own provider, and only when every master holds it are the secrets re-sealed with it. Each master
then drops the old key and compacts its Raft log, so nothing sealed with the old key remains.
Remove dead masters first ('cluster member rm'): the rotation waits for every master.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		return withState(func(st *ClusterState) error {
			switch {
			case st.DEKID == "":
				return fmt.Errorf("the secrets are not sealed yet (every master must run this version)")
			case st.NextDEKID != "":
				return fmt.Errorf("a rotation to %s is in progress (cluster keys status)", st.NextDEKID)
			}
			st.DEKRotateRequested = time.Now()
			fmt.Println("✓ data key rotation requested; follow it with: ziroctl cluster keys status")
			return nil
		})
	},
}

func init() {
	clusterKeysCmd.AddCommand(clusterKeysRotateCmd)
	clusterKeysProviderCmd.Flags().StringVar(&keysWrap, "wrap", "", "command provider: wrap executable")
	clusterKeysProviderCmd.Flags().StringVar(&keysUnwrap, "unwrap", "", "command provider: unwrap executable")
	clusterKeysCmd.AddCommand(clusterKeysStatusCmd, clusterKeysProviderCmd)
	clusterCmd.AddCommand(clusterKeysCmd)
}
