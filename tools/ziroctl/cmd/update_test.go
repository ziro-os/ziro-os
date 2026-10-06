package cmd

import (
	"bytes"
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
	"strings"
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

func TestAvailableWithBuilderVersions(t *testing.T) {
	for _, c := range []struct {
		current, latest string
		want            bool
	}{
		{"1.0.21.3", "1.0.21", false},   // the OS-bundled build is older than a builder release: no downgrade
		{"1.0.21.3", "1.0.21.3", false}, // equal, not available forever
		{"1.0.21.3", "1.0.21.4", true},
		{"1.0.21.9", "1.0.21.10", true}, // numeric
		{"1.0.21", "1.0.21.1", true},
		{"1.0.21.7", "1.0.22", true},
		{"v1.0.21.3", "1.0.21.3", false},
		{"dev", "1.0.21.1", true},
	} {
		if got := (UpdateCheck{Current: c.current, Latest: c.latest}).Available(); got != c.want {
			t.Errorf("Available(%s → %s) = %v, want %v", c.current, c.latest, got, c.want)
		}
	}
}

func TestLatestToolsReleaseMixedTags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/" + upgradeRepo + "/git/matching-refs/tags/tools/v":
			// .10 beats .9 (numeric), and neither a .0 spelling nor a prerelease suffix is a release
			fmt.Fprint(w, `[{"ref":"refs/tags/tools/v1.0.21"},{"ref":"refs/tags/tools/v1.0.21.9"},{"ref":"refs/tags/tools/v1.0.21.10"},{"ref":"refs/tags/tools/v1.0.21.11.1"},{"ref":"refs/tags/tools/v1.0.22.0"},{"ref":"refs/tags/tools/v1.0.22-rc1"}]`)
		case "/repos/" + upgradeRepo + "/releases/tags/tools/v1.0.21.10":
			fmt.Fprint(w, `{"tag_name":"tools/v1.0.21.10","assets":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = old }()
	rel, v, err := latestToolsRelease(context.Background())
	if err != nil || v != "1.0.21.10" || rel.TagName != "tools/v1.0.21.10" {
		t.Fatalf("got %v %q %v", rel, v, err)
	}
}

func TestResolveToolsTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/"+upgradeRepo+"/git/matching-refs/tags/tools/v":
			fmt.Fprint(w, `[{"ref":"refs/tags/tools/v1.0.21"},{"ref":"refs/tags/tools/v1.0.21.3"},{"ref":"refs/tags/tools/v1.0.21.4"}]`)
		case strings.Contains(r.URL.Path, "/releases/tags/tools/v"):
			tag := r.URL.Path[strings.Index(r.URL.Path, "tools/v"):]
			fmt.Fprintf(w, `{"tag_name":%q,"prerelease":%v,"assets":[]}`, tag, tag == "tools/v1.0.21.2")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	oldAPI, oldVer := githubAPI, Version
	githubAPI, Version = srv.URL, "1.0.21.3"
	defer func() { githubAPI, Version = oldAPI, oldVer }()
	ctx := context.Background()

	// newest: newer than running installs, equal is up to date
	if rel, v, err := resolveToolsTarget(ctx, "", false); err != nil || rel == nil || v != "1.0.21.4" {
		t.Fatalf("newest: %v %q %v", rel, v, err)
	}
	Version = "1.0.21.4"
	if rel, _, err := resolveToolsTarget(ctx, "", false); err != nil || rel != nil {
		t.Fatalf("up to date: %v %v", rel, err)
	}
	Version = "1.0.21.3"

	for _, c := range []struct {
		tag       string
		downgrade bool
		want      string // installed version; "" = nothing to do
		wantErr   string
	}{
		{"v1.0.21.4", false, "1.0.21.4", ""},
		{"tools/v1.0.21.4", false, "1.0.21.4", ""},
		{"1.0.21.3", false, "", ""},                   // the running version: already installed
		{"v1.0.21", false, "", "--allow-downgrade"},   // older: refused
		{"v1.0.21", true, "1.0.21", ""},               // older, but asked for
		{"v1.0.21.0", true, "", "invalid version"},    // not a canonical version
		{"v1.0.21.3.1", false, "", "invalid version"}, // five parts
		{"latest", false, "", "invalid version"},
		{"v1.0.21.2", true, "", "not a published"}, // a prerelease is never installed
	} {
		rel, v, err := resolveToolsTarget(ctx, c.tag, c.downgrade)
		switch {
		case c.wantErr != "":
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%s (downgrade=%v): err %v, want %q", c.tag, c.downgrade, err, c.wantErr)
			}
		case err != nil:
			t.Errorf("%s: %v", c.tag, err)
		case (rel == nil) != (c.want == "") || v != c.want:
			t.Errorf("%s (downgrade=%v): got %v %q, want %q", c.tag, c.downgrade, rel, v, c.want)
		}
	}
}

func TestToolsReleaseRefusesRelabelledMeta(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	oldKey, oldBin := releasePublicKey, toolsBinDir
	releasePublicKey = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	toolsBinDir = t.TempDir()
	defer func() { releasePublicKey, toolsBinDir = oldKey, oldBin }()

	try := func(tag, metaJSON string) error {
		files := map[string][]byte{"ziroctl-" + hostArch(): []byte("ctl"), "ziropkg-" + hostArch(): []byte("pkg"), "tools.json": []byte(metaJSON)}
		sums := ""
		for n, b := range files {
			sums += sha256Hex(b) + "  " + n + "\n"
		}
		files["SHA256SUMS"] = []byte(sums)
		files["SHA256SUMS.sig"] = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(sums))))
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(files[filepath.Base(r.URL.Path)]) }))
		defer srv.Close()
		trustHTTPS(t, srv)
		rel := &ghRelease{TagName: tag}
		for n := range files {
			rel.Assets = append(rel.Assets, ghAsset{Name: n, URL: srv.URL + "/" + n})
		}
		_, err := fetchToolsRelease(rel, t.TempDir())
		return err
	}
	if err := try("tools/v1.0.21.4", `{"version":"1.0.21.4","min_os":"1.0.16"}`); err != nil {
		t.Fatalf("honest release: %v", err)
	}
	if err := try("tools/v1.0.21.4", `{"version":"1.0.21.3","min_os":"1.0.16"}`); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("an older build re-published under a newer tag was accepted: %v", err)
	}
	if err := try("v1.0.21.4", `{"version":"1.0.21.4"}`); err == nil {
		t.Fatal("a non-tools tag was accepted")
	}
}

func TestReportedVersion(t *testing.T) {
	for out, want := range map[string]string{
		"ziroctl version 1.0.21.3 (os 1.0.21, linux/amd64)\nGit Commit: x\n": "1.0.21.3",
		"ziropkg version 1.0.21\n": "1.0.21",
		"1.0.21.3\n":               "1.0.21.3",
		"v1.0.21.3\n":              "1.0.21.3",
		"":                         "",
		"usage: nonsense here\n":   "",
	} {
		if got := reportedVersion(out); got != want {
			t.Errorf("reportedVersion(%q) = %q, want %q", out, got, want)
		}
	}
}

func TestCheckStaged(t *testing.T) {
	dir := t.TempDir()
	script := func(name, body string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0755)
		return p
	}
	good := script("good", `echo "ziropkg version 1.0.21.4"`)
	if err := checkStaged(good, "1.0.21.4"); err != nil {
		t.Fatalf("matching version: %v", err)
	}
	// a build whose version was never stamped would be "available" forever
	if err := checkStaged(good, "1.0.21.5"); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("version mismatch accepted: %v", err)
	}
	if err := checkStaged(script("crash", "exit 3"), "1.0.21.4"); err == nil || !strings.Contains(err.Error(), "does not run") {
		t.Fatalf("crashing binary accepted: %v", err)
	}
	if err := checkStaged(filepath.Join(dir, "missing"), "1.0.21.4"); err == nil {
		t.Fatal("missing binary accepted")
	}
}

func TestKeepNewerTools(t *testing.T) {
	for _, c := range []struct {
		running, targetOS string
		want              bool
	}{
		{"1.0.21.3", "1.0.21", true},  // a build made since the image: kept
		{"1.0.21.3", "1.0.22", false}, // the next OS ships newer tools
		{"1.0.21", "1.0.21", false},   // the same build: nothing to keep
		{"v1.0.22", "1.0.21", true},   // tools newer than the target OS (ziroctl update before upgrade)
		{"1.0.20.9", "1.0.21", false},
		{"dev", "1.0.21", false},
	} {
		if got := keepNewerTools(c.running, c.targetOS); got != c.want {
			t.Errorf("keepNewerTools(%s, %s) = %v, want %v", c.running, c.targetOS, got, c.want)
		}
	}
	dir := t.TempDir()
	old := toolsBinDir
	toolsBinDir = dir
	defer func() { toolsBinDir = old }()
	if got := toolsToKeep(); len(got) != 2 {
		t.Fatalf("without zirocd: %v", got)
	}
	os.WriteFile(filepath.Join(dir, "zirocd"), []byte("x"), 0755)
	if got := toolsToKeep(); len(got) != 3 || got[2] != "zirocd" {
		t.Fatalf("with zirocd: %v", got)
	}
}

func TestNormalizeClientVersion(t *testing.T) {
	for _, c := range []struct {
		in      string
		set     bool
		want    string
		wantErr bool
	}{
		{"1.0.21", true, "1.0.21", false},
		{"v1.0.21.3", true, "1.0.21.3", false},
		{"latest", true, "", false},
		{"", false, "", false},
		{"1.0.21.0", true, "", true},
		{"1.0.21.3.1", true, "", true},
		{"1.0", true, "", true},
		{"banana", true, "", true},
	} {
		got, err := normalizeClientVersion(c.in, c.set)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("normalizeClientVersion(%q) = %q, %v", c.in, got, err)
		}
	}
}

// The source defaults are the OS-bundled build (N = 0): exactly the VERSION file. A drifted
// default (release.sh forgot a file) would make `ziroctl update` offer or skip builds wrongly.
func TestSourceVersionsMatchVERSIONFile(t *testing.T) {
	want, err := os.ReadFile("../../../VERSION")
	if err != nil {
		t.Skip("no VERSION file")
	}
	v := strings.TrimSpace(string(want))
	if Version != v {
		t.Errorf("cmd.Version = %q, VERSION = %q", Version, v)
	}
	pkg, err := os.ReadFile("../../ziropkg/cmd/root.go")
	if err != nil {
		t.Skip("no ziropkg source")
	}
	if !strings.Contains(string(pkg), `Version = "`+v+`"`) {
		t.Errorf("ziropkg/cmd/root.go Version default does not match VERSION %s", v)
	}
}

func TestMOTDShowsOSAndToolsVersions(t *testing.T) {
	var buf bytes.Buffer
	renderMOTD(&buf, HostSummary{Version: "1.0.21.3", OSVersion: "1.0.21", Hostname: "h", Mode: "installed"}, termStyle{})
	out := buf.String()
	if !strings.Contains(out, "Ziro OS 1.0.21") || strings.Contains(out, "Ziro OS 1.0.21.3") || !strings.Contains(out, "Tools") || !strings.Contains(out, "ziroctl 1.0.21.3") {
		t.Errorf("motd:\n%s", out)
	}
	buf.Reset()
	renderMOTD(&buf, HostSummary{Version: "1.0.21", OSVersion: "1.0.21", Hostname: "h", Mode: "installed"}, termStyle{})
	if strings.Contains(buf.String(), "Tools") {
		t.Errorf("tools row shown when they match the OS:\n%s", buf.String())
	}
}
