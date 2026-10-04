package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ziro-os/ziro-os/sdk/release"
)

// fakeReleases serves a tools release stream signed with a test key.
func fakeReleases(t *testing.T, bins map[string][]byte, tamper bool) *release.Source {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	var sums strings.Builder
	for name, b := range bins {
		h := sha256.Sum256(b)
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(h[:]), name)
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(sums.String())))
	if tamper {
		for name := range bins {
			bins[name] = append(bins[name], '!')
		}
	}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/git/matching-refs/tags/tools/v"):
			fmt.Fprint(w, `[{"ref":"refs/tags/tools/v1.0.1"},{"ref":"refs/tags/tools/v1.0.9"},{"ref":"refs/tags/v2.0.0"}]`)
		case strings.Contains(r.URL.Path, "/releases/tags/tools/v"):
			tag := r.URL.Path[strings.Index(r.URL.Path, "tools/v"):]
			fmt.Fprintf(w, `{"tag_name":%q,"assets":[`, tag)
			fmt.Fprintf(w, `{"name":"SHA256SUMS","browser_download_url":"%s/dl/SHA256SUMS"},{"name":"SHA256SUMS.sig","browser_download_url":"%s/dl/sig"}`, srv.URL, srv.URL)
			for name := range bins {
				fmt.Fprintf(w, `,{"name":%q,"browser_download_url":"%s/dl/%s"}`, name, srv.URL, name)
			}
			fmt.Fprint(w, `]}`)
		case r.URL.Path == "/dl/SHA256SUMS":
			fmt.Fprint(w, sums.String())
		case r.URL.Path == "/dl/sig":
			fmt.Fprint(w, sig)
		case strings.HasPrefix(r.URL.Path, "/dl/"):
			w.Write(bins[strings.TrimPrefix(r.URL.Path, "/dl/")])
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	s := release.NewSource("test")
	s.API, s.HTTP = srv.URL, srv.Client()
	s.PublicKey = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	s.Trusted = func(u *url.URL) bool { return u.Scheme == "https" }
	return s
}

func TestUpdateInstallAndRollback(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "zirocd")
	os.WriteFile(exe, []byte("old"), 0755)
	u := &Updater{Current: "1.0.1", Exe: exe, Dir: dir, Source: fakeReleases(t, map[string][]byte{AssetName(): []byte("new")}, false)}
	ctx := context.Background()

	v, err := u.Target(ctx, "")
	if err != nil || v != "1.0.9" {
		t.Fatalf("target: %q %v", v, err)
	}
	if v, _ := u.Target(ctx, "1.0.1"); v != "" {
		t.Fatal("pinned to the running version must stay")
	}
	if v, _ := u.Target(ctx, "1.0.0"); v != "1.0.0" {
		t.Fatal("an admin pin may roll back")
	}
	if err := u.Install(ctx, v); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "new" {
		t.Fatal("binary not swapped")
	}
	if b, _ := os.ReadFile(exe + ".prev"); string(b) != "old" {
		t.Fatal("previous binary not kept")
	}
	// Two starts may fail; the third rolls back to the previous binary.
	for i := 0; i < 2; i++ {
		if rb, err := u.Startup(); rb || err != nil {
			t.Fatalf("start %d rolled back early: %v", i, err)
		}
	}
	if rb, err := u.Startup(); !rb || err != nil {
		t.Fatalf("no rollback: %v", err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatal("rollback did not restore the previous binary")
	}
	// A healthy start clears the marker: no rollback later.
	u.Install(ctx, "1.0.9")
	u.Healthy()
	for i := 0; i < 4; i++ {
		if rb, _ := u.Startup(); rb {
			t.Fatal("rolled back a healthy update")
		}
	}
}

func TestUpdateRefusesTamperedBinary(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "zirocd")
	os.WriteFile(exe, []byte("old"), 0755)
	u := &Updater{Current: "1.0.1", Exe: exe, Dir: dir, Source: fakeReleases(t, map[string][]byte{AssetName(): []byte("new")}, true)}
	if err := u.Install(context.Background(), "1.0.9"); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("tampered binary: %v", err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatal("binary changed despite a failed verification")
	}
	// A signature from another key is refused before any binary is fetched.
	u.Source.PublicKey = release.PublicKey
	if err := u.Install(context.Background(), "1.0.9"); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("foreign signature: %v", err)
	}
}
