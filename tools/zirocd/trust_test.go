package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A host with a self-signed certificate: deploy fails with a hint, zirocd trust (checked by
// fingerprint) fixes it, a different fingerprint is refused.
func TestSelfSignedHost(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("HOME", cfg)
	t.Setenv("XDG_CONFIG_HOME", cfg)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/source"):
			json.NewEncoder(w).Encode(map[string]string{"id": "b1"})
		case strings.HasSuffix(r.URL.Path, "/log"):
			io.WriteString(w, "ok\n")
		default:
			json.NewEncoder(w).Encode(map[string]any{"url": "http://x", "builds": []map[string]string{{"id": "b1", "status": "live"}}})
		}
	}))
	defer srv.Close()
	dir := filepath.Join(t.TempDir(), "site")
	os.Mkdir(dir, 0755)
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("hi"), 0644)
	tok := filepath.Join(t.TempDir(), "tok")
	os.WriteFile(tok, []byte("t"), 0600)
	run := func(args ...string) error {
		root := newRoot()
		root.SetArgs(args)
		return root.Execute()
	}
	deploy := func(extra ...string) error {
		return run(append([]string{"deploy", dir, "--host", srv.URL, "--token-file", tok, "--no-follow"}, extra...)...)
	}

	err := deploy()
	if err == nil || !strings.Contains(err.Error(), "zirocd trust "+srv.URL) {
		t.Fatalf("untrusted self-signed host: %v", err)
	}
	if run("trust", srv.URL, "--fingerprint", "sha256:"+strings.Repeat("0", 64)) == nil {
		t.Fatal("trusted a certificate with the wrong fingerprint")
	}
	if deploy() == nil {
		t.Fatal("a refused trust still let the deploy through")
	}
	fp := fingerprint(srv.Certificate().Raw)
	if err := run("trust", srv.URL, "--fingerprint", fp); err != nil {
		t.Fatal(err)
	}
	if err := deploy(); err != nil {
		t.Fatalf("after trust: %v", err)
	}
	if err := run("trust", srv.URL, "--remove"); err != nil || deploy() == nil {
		t.Fatalf("after --remove the host should be untrusted again (%v)", err)
	}
	if _, err := hostPort("http://10.0.0.5:8443"); err == nil {
		t.Error("trust accepted a plain http URL")
	}
}
