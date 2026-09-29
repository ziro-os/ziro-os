package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAPITokens(t *testing.T) {
	old := apiTokensFile
	apiTokensFile = filepath.Join(t.TempDir(), "api-tokens.json")
	defer func() { apiTokensFile = old }()
	now := time.Now()

	mk := func(name, role string, expires time.Time) string {
		tok := "ziro_" + randomHex(4) + "_" + randomHex(24)
		sum := sha256.Sum256([]byte(tok))
		ts, _ := loadAPITokens()
		e := ""
		if !expires.IsZero() {
			e = expires.Format(time.RFC3339)
		}
		ts = append(ts, apiToken{ID: tok[5:13], Name: name, Role: role, Hash: hex.EncodeToString(sum[:]), Expires: e})
		if err := saveAPITokens(ts); err != nil {
			t.Fatal(err)
		}
		return tok
	}
	viewer := mk("grafana", "viewer", time.Time{})
	op := mk("ci", "operator", now.Add(time.Hour))
	expired := mk("old", "admin", now.Add(-time.Minute))

	if raw, _ := os.ReadFile(apiTokensFile); bytes.Contains(raw, []byte(viewer[13:])) {
		t.Fatal("token secret stored in clear")
	}
	if fi, _ := os.Stat(apiTokensFile); fi.Mode().Perm() != 0600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	cases := []struct {
		tok, name, role string
		ok              bool
	}{
		{"legacy-secret", "legacy-token", "admin", true},
		{viewer, "grafana", "viewer", true},
		{op, "ci", "operator", true},
		{expired, "", "", false},
		{viewer[:len(viewer)-4] + "0000", "", "", false}, // right id, wrong secret
		{"ziro_zz_nothex", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		name, role, ok := apiIdentity(c.tok, "legacy-secret", now)
		if ok != c.ok || name != c.name || role != c.role {
			t.Errorf("%q: got %q %q %v", c.tok, name, role, ok)
		}
	}
	if _, _, ok := apiIdentity("", "", now); ok {
		t.Error("an empty legacy token must not match an empty bearer")
	}
	for _, c := range []struct {
		role, method string
		ok           bool
	}{
		{"viewer", http.MethodGet, true}, {"viewer", http.MethodPost, false}, {"viewer", http.MethodDelete, false},
		{"operator", http.MethodPost, true}, {"admin", http.MethodPut, true}, {"", http.MethodGet, false},
	} {
		if apiAllowed(c.role, c.method) != c.ok {
			t.Errorf("%s %s: want %v", c.role, c.method, c.ok)
		}
	}
}

func TestNodeTokenRotation(t *testing.T) {
	now := time.Now()
	st := &ClusterState{NodeTokens: map[string]string{"n1": hashToken("old")},
		Nodes: []ClusterNode{{ID: "n1", TokenIssued: now.Add(-time.Hour)}}}
	auth := func(tok string, at time.Time) (bool, error) {
		_, prev, err := authNodeToken(st, "Bearer n1."+tok, at)
		return prev, err
	}
	if prev, err := auth("old", now); err != nil || prev {
		t.Fatal("current token")
	}
	if needsTokenRotation(st, st.node("n1"), false, now) {
		t.Fatal("a fresh token must not rotate")
	}
	if !needsTokenRotation(st, st.node("n1"), false, now.Add(31*24*time.Hour)) {
		t.Fatal("tokens older than 30 days rotate")
	}
	st.RotateTokensBefore = now
	if !needsTokenRotation(st, st.node("n1"), false, now) {
		t.Fatal("forced rotation")
	}
	if err := rotateNodeToken(st, st.node("n1"), "not-hex", now); err == nil {
		t.Fatal("malformed token accepted")
	}
	newTok := strings.Repeat("ab", 32)
	if err := rotateNodeToken(st, st.node("n1"), newTok, now); err != nil {
		t.Fatal(err)
	}
	if needsTokenRotation(st, st.node("n1"), false, now) {
		t.Fatal("rotated token must satisfy the forced rotation")
	}
	if prev, err := auth(newTok, now); err != nil || prev {
		t.Fatal("new token")
	}
	// The reply was lost: the old token still works for an hour and asks for another rotation.
	prev, err := auth("old", now.Add(30*time.Minute))
	if err != nil || !prev || !needsTokenRotation(st, st.node("n1"), prev, now) {
		t.Fatalf("previous token within the grace: prev=%v err=%v", prev, err)
	}
	if _, err := auth("old", now.Add(61*time.Minute)); err == nil {
		t.Fatal("previous token accepted after the grace")
	}
	if _, err := auth("wrong", now); err == nil {
		t.Fatal("wrong token accepted")
	}
}

func TestCertRotation(t *testing.T) {
	old := clusterDir
	clusterDir = t.TempDir()
	defer func() { clusterDir = old }()
	st := &ClusterState{}
	if err := ensureCA(st); err != nil {
		t.Fatal(err)
	}
	ips := []net.IP{net.ParseIP("127.0.0.1")}
	if err := ensureMasterCert(st, "m1", ips); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(masterCertPath())
	if err := ensureMasterCert(st, "m1", ips); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(masterCertPath()); !bytes.Equal(first, again) {
		t.Fatal("a valid certificate was re-issued")
	}
	time.Sleep(1100 * time.Millisecond) // certificate times have one-second resolution
	st.RotateCertsBefore = time.Now()
	if err := ensureMasterCert(st, "m1", ips); err != nil {
		t.Fatal(err)
	}
	rotated, _ := os.ReadFile(masterCertPath())
	if bytes.Equal(first, rotated) {
		t.Fatal("rotation did not re-issue the certificate")
	}
	if err := ensureMasterCert(st, "m1", ips); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(masterCertPath()); !bytes.Equal(rotated, again) {
		t.Fatal("rotation must happen once, not on every check")
	}
	// Refuses to mint a second CA over an existing one.
	st.CAKey = ""
	if err := ensureCA(st); err == nil {
		t.Fatal("ensureCA replaced a CA whose key is missing")
	}
}
