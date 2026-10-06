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
	return fakeStream(t, bins, tamper, []string{"1.0.1", "1.0.9"}, func(v string) string { return v })
}

// fakeStream serves the given tools tags (plus an OS tag that must be ignored). metaVersion
// gives the version each release's signed tools.json claims.
func fakeStream(t *testing.T, bins map[string][]byte, tamper bool, versions []string, metaVersion func(string) string) *release.Source {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	hashes := map[string]string{}
	for name, b := range bins {
		h := sha256.Sum256(b)
		hashes[name] = hex.EncodeToString(h[:])
	}
	if tamper {
		for name := range bins {
			bins[name] = append(bins[name], '!')
		}
	}
	// per version: tools.json, SHA256SUMS and its signature
	toolsJSON := func(v string) []byte {
		return []byte(fmt.Sprintf(`{"version":%q,"min_os":"1.0.16"}`, metaVersion(v)))
	}
	sumsFor := func(v string) string {
		var sums strings.Builder
		for name, h := range hashes {
			fmt.Fprintf(&sums, "%s  %s\n", h, name)
		}
		mh := sha256.Sum256(toolsJSON(v))
		fmt.Fprintf(&sums, "%s  tools.json\n", hex.EncodeToString(mh[:]))
		return sums.String()
	}
	var refs []string
	for _, v := range versions {
		refs = append(refs, fmt.Sprintf(`{"ref":"refs/tags/tools/v%s"}`, v))
	}
	refs = append(refs, `{"ref":"refs/tags/tools/v1.0.21-rc1"}`, `{"ref":"refs/tags/v2.0.0"}`)
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/git/matching-refs/tags/tools/v"):
			fmt.Fprintf(w, "[%s]", strings.Join(refs, ","))
		case strings.Contains(r.URL.Path, "/releases/tags/tools/v"):
			tag := r.URL.Path[strings.Index(r.URL.Path, "tools/v"):]
			v := strings.TrimPrefix(tag, "tools/v")
			fmt.Fprintf(w, `{"tag_name":%q,"assets":[`, tag)
			fmt.Fprintf(w, `{"name":"SHA256SUMS","browser_download_url":"%s/dl/%s/SHA256SUMS"},{"name":"SHA256SUMS.sig","browser_download_url":"%s/dl/%s/sig"},{"name":"tools.json","browser_download_url":"%s/dl/%s/tools.json"}`, srv.URL, v, srv.URL, v, srv.URL, v)
			for name := range bins {
				fmt.Fprintf(w, `,{"name":%q,"browser_download_url":"%s/dl/%s/%s"}`, name, srv.URL, v, name)
			}
			fmt.Fprint(w, `]}`)
		case strings.HasPrefix(r.URL.Path, "/dl/"):
			f := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/dl/"), "/", 2)
			switch f[1] {
			case "SHA256SUMS":
				fmt.Fprint(w, sumsFor(f[0]))
			case "sig":
				fmt.Fprint(w, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(sumsFor(f[0])))))
			case "tools.json":
				w.Write(toolsJSON(f[0]))
			default:
				w.Write(bins[f[1]])
			}
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

func TestTargetWithBuilderVersions(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "zirocd")
	os.WriteFile(exe, []byte("old"), 0755)
	src := fakeStream(t, map[string][]byte{AssetName(): []byte("new")}, false,
		[]string{"1.0.21", "1.0.21.1", "1.0.21.9", "1.0.21.10", "1.0.9"}, func(v string) string { return v })
	ctx := context.Background()
	for _, c := range []struct{ current, pin, want string }{
		{"1.0.21.3", "", "1.0.21.10"},    // numeric, not lexical: .10 is newer than .9
		{"1.0.21.10", "", ""},            // already the newest build: stay
		{"1.0.21", "", "1.0.21.10"},      // the OS-bundled build takes the builder releases
		{"1.0.22", "", ""},               // a newer OS's tools are not downgraded to a build of the older OS
		{"1.0.21.3", "1.0.21.3", ""},     // a pin on the running version stays
		{"1.0.21.3", "1.0.21", "1.0.21"}, // an admin pin may go back
	} {
		u := &Updater{Current: c.current, Exe: exe, Dir: dir, Source: src}
		if got, err := u.Target(ctx, c.pin); err != nil || got != c.want {
			t.Errorf("Target(current %s, pin %q) = %q, %v; want %q", c.current, c.pin, got, err, c.want)
		}
	}
	// 1.0.21-rc1 and a pin that is not a canonical tools version are never offered.
	u := &Updater{Current: "1.0.21.3", Exe: exe, Dir: dir, Source: src}
	if err := u.Install(ctx, "1.0.21.0"); err == nil {
		t.Fatal("a .0 pin was accepted")
	}
	if err := u.Install(ctx, "1.0.21.10"); err != nil {
		t.Fatal(err)
	}
}

func TestInstallRefusesRelabelledRelease(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "zirocd")
	os.WriteFile(exe, []byte("old"), 0755)
	// every release's signed tools.json claims 1.0.1: a signed old build re-published under a newer tag
	src := fakeStream(t, map[string][]byte{AssetName(): []byte("new")}, false, []string{"1.0.1", "1.0.21.2"}, func(string) string { return "1.0.1" })
	u := &Updater{Current: "1.0.1", Exe: exe, Dir: dir, Source: src}
	if err := u.Install(context.Background(), "1.0.21.2"); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("re-labelled release installed: %v", err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatal("binary changed")
	}
}
