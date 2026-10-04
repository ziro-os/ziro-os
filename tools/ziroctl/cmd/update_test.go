package cmd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyReleaseSums(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	sums := []byte("abc  ziroctl-x86_64\n")
	sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, sums)) + "\n")
	if err := verifyReleaseSums(sums, sig, pubPEM); err != nil {
		t.Fatal(err)
	}
	if verifyReleaseSums([]byte("abd  ziroctl-x86_64\n"), sig, pubPEM) == nil {
		t.Error("tampered sums accepted")
	}
	if verifyReleaseSums(sums, []byte("bm90IGEgc2ln"), pubPEM) == nil || verifyReleaseSums(sums, sig, releasePublicKey) == nil {
		t.Error("bad signature or wrong key accepted")
	}
}

func TestInstallTool(t *testing.T) {
	dir := t.TempDir()
	oldBin, oldLink := toolsBinDir, toolsLinkDir
	toolsBinDir, toolsLinkDir = filepath.Join(dir, "usr-bin"), filepath.Join(dir, "bin")
	defer func() { toolsBinDir, toolsLinkDir = oldBin, oldLink }()
	os.MkdirAll(toolsBinDir, 0755)
	os.MkdirAll(toolsLinkDir, 0755)
	os.WriteFile(filepath.Join(toolsBinDir, "ziroctl"), []byte("old"), 0755)
	os.WriteFile(filepath.Join(toolsLinkDir, "ziroctl"), []byte("old copy"), 0755)
	src := filepath.Join(dir, "new")
	os.WriteFile(src, []byte("new"), 0600)

	if err := installTool("ziroctl", src); err != nil {
		t.Fatal(err)
	}
	read := func(p string) string { b, _ := os.ReadFile(p); return string(b) }
	if read(filepath.Join(toolsBinDir, "ziroctl")) != "new" || read(filepath.Join(toolsBinDir, "ziroctl.prev")) != "old" {
		t.Error("swap")
	}
	if fi, _ := os.Stat(filepath.Join(toolsBinDir, "ziroctl")); fi.Mode().Perm() != 0755 {
		t.Error("mode", fi.Mode())
	}
	if l, _ := os.Readlink(filepath.Join(toolsLinkDir, "ziroctl")); l != filepath.Join(toolsBinDir, "ziroctl") {
		t.Error("bin link", l)
	}
	if !(UpdateCheck{Current: "1.0.16", Latest: "1.1.0"}).Available() || (UpdateCheck{Current: "v1.1.0", Latest: "1.1.0"}).Available() {
		t.Error("Available")
	}
}

func TestLatestToolsRelease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/" + upgradeRepo + "/git/matching-refs/tags/tools/v":
			fmt.Fprint(w, `[{"ref":"refs/tags/tools/v1.0.9"},{"ref":"refs/tags/tools/v1.0.17"},{"ref":"refs/tags/tools/vbad"}]`)
		case "/repos/" + upgradeRepo + "/releases/tags/tools/v1.0.17":
			fmt.Fprint(w, `{"tag_name":"tools/v1.0.17","assets":[{"name":"SHA256SUMS"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = old }()
	rel, v, err := latestToolsRelease(context.Background())
	if err != nil || v != "1.0.17" || rel.TagName != "tools/v1.0.17" || rel.asset("SHA256SUMS") == nil {
		t.Fatalf("got %v %q %v", rel, v, err)
	}
}

// zirocd is optional: installed by `ziroctl update` only where the image has it and the release
// carries it, so older releases and images keep updating.
func TestToolsReleaseOptionalZirocd(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	oldKey, oldBin := releasePublicKey, toolsBinDir
	releasePublicKey = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	toolsBinDir = t.TempDir()
	defer func() { releasePublicKey, toolsBinDir = oldKey, oldBin }()

	serve := func(withZirocd bool) *ghRelease {
		files := map[string][]byte{"ziroctl-" + hostArch(): []byte("ctl"), "ziropkg-" + hostArch(): []byte("pkg"),
			"tools.json": []byte(`{"version":"1.0.30"}`)}
		if withZirocd {
			files[toolAsset("zirocd")] = []byte("cd")
		}
		sums := ""
		for n, b := range files {
			sums += sha256Hex(b) + "  " + n + "\n"
		}
		files["SHA256SUMS"] = []byte(sums)
		files["SHA256SUMS.sig"] = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(sums))))
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(files[filepath.Base(r.URL.Path)])
		}))
		t.Cleanup(srv.Close)
		trustHTTPS(t, srv)
		rel := &ghRelease{TagName: "tools/v1.0.30"}
		for n := range files {
			rel.Assets = append(rel.Assets, ghAsset{Name: n, URL: srv.URL + "/" + n})
		}
		return rel
	}
	get := func(rel *ghRelease) map[string]string {
		bins, err := fetchToolsRelease(rel, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return bins
	}
	if bins := get(serve(true)); bins["zirocd"] != "" || len(installedTools(bins)) != 2 {
		t.Fatal("zirocd installed on a host without it")
	}
	os.WriteFile(filepath.Join(toolsBinDir, "zirocd"), []byte("old"), 0755)
	if bins := get(serve(true)); bins["zirocd"] == "" || len(installedTools(bins)) != 3 {
		t.Fatal("zirocd not updated on a host that has it")
	}
	if bins := get(serve(false)); bins["zirocd"] != "" { // a release from before zirocd
		t.Fatal("missing optional asset must be skipped")
	}
}

// trustHTTPS lets download() reach a test TLS server.
func trustHTTPS(t *testing.T, srv *httptest.Server) {
	u, _ := url.Parse(srv.URL)
	oldHosts, oldClient := trustedHosts, upgradeHTTP
	trustedHosts = append([]string{u.Hostname()}, trustedHosts...)
	upgradeHTTP = &http.Client{Transport: srv.Client().Transport, CheckRedirect: checkUpgradeRedirect}
	t.Cleanup(func() { trustedHosts, upgradeHTTP = oldHosts, oldClient })
}
