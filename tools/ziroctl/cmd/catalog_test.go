package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/ziro-os/ziro-os/sdk/catalog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCatalogKey(t *testing.T) (pubPEM string, privPEM []byte) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pb, _ := x509.MarshalPKIXPublicKey(pub)
	sb, _ := x509.MarshalPKCS8PrivateKey(priv)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pb})),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: sb})
}

// publishCatalog builds and signs a module catalog from manifests into dir.
func publishCatalog(t *testing.T, dir string, priv []byte, mods ...ModuleManifest) {
	t.Helper()
	src := t.TempDir()
	for _, m := range mods {
		p := filepath.Join(src, "modules", m.Name, "manifest.json")
		os.MkdirAll(filepath.Dir(p), 0755)
		b, _ := json.Marshal(m)
		os.WriteFile(p, b, 0644)
	}
	if _, err := catalog.Build(src, dir, "test", "module", 24*time.Hour, catalogNow(), catalogCheckers["module"]); err != nil {
		t.Fatal(err)
	}
	if err := catalog.Sign(dir, priv); err != nil {
		t.Fatal(err)
	}
}

// serveCatalog serves dir over TLS and makes it the only official module repo.
func serveCatalog(t *testing.T, pub string) (dir string, repo CatalogRepo) {
	dir = t.TempDir()
	srv := httptest.NewTLSServer(http.FileServer(http.Dir(dir)))
	t.Cleanup(srv.Close)
	oldHTTP, oldRepos := catalogHTTP, officialRepos
	catalogHTTP = srv.Client()
	repo = CatalogRepo{Name: "ziro", URL: srv.URL, Kind: "module", Key: pub, Official: true}
	officialRepos = []CatalogRepo{repo}
	t.Cleanup(func() { catalogHTTP, officialRepos = oldHTTP, oldRepos })
	return dir, repo
}

var demoPlugin = ModuleManifest{Name: "demo-plugin", Version: "1.0", Description: "demo", Packages: []string{"demo"}}

func TestCatalogRefreshVerifyAndLoad(t *testing.T) {
	stubModules(t)
	pub, priv := testCatalogKey(t)
	dir, repo := serveCatalog(t, pub)
	// A catalog entry named like a built-in module can't shadow it.
	shadow := ModuleManifest{Name: "clamav", Version: "9.9", Description: "evil"}
	publishCatalog(t, dir, priv, demoPlugin, shadow)
	if _, err := refreshRepo(repo); err != nil {
		t.Fatal(err)
	}
	all, _ := loadManifests()
	if all["demo-plugin"].Source != "ziro" || all["clamav"].Source != "builtin" || all["clamav"].Version == "9.9" {
		t.Fatalf("demo=%+v clamav=%+v", all["demo-plugin"], all["clamav"])
	}

	// Tampering with the cache is detected on read.
	entry := filepath.Join(repoCache(repo), "entries", "modules", "demo-plugin.json")
	os.WriteFile(entry, []byte(`{"name":"demo-plugin","version":"1.0","packages":["backdoor"]}`), 0644)
	if all, _ := loadManifests(); all["demo-plugin"].Name != "" {
		t.Fatal("tampered cache entry accepted")
	}

	// A bad signature fails the refresh and leaves the cache alone.
	publishCatalog(t, dir, priv, demoPlugin)
	_, otherPriv := testCatalogKey(t)
	catalog.Sign(dir, otherPriv)
	before, _ := os.ReadFile(filepath.Join(repoCache(repo), "index.json"))
	if _, err := refreshRepo(repo); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("bad signature: %v", err)
	}
	if after, _ := os.ReadFile(filepath.Join(repoCache(repo), "index.json")); string(after) != string(before) {
		t.Fatal("failed refresh replaced the cache")
	}

	// Rollback: an older (validly signed) index is refused.
	defer func() { catalogNow = time.Now }()
	catalogNow = func() time.Time { return time.Now().Add(-time.Hour) }
	publishCatalog(t, dir, priv, demoPlugin)
	catalogNow = time.Now
	if _, err := refreshRepo(repo); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("rollback: %v", err)
	}

	// Freeze: an expired index is refused, also from the cache.
	catalogNow = func() time.Time { return time.Now().Add(48 * time.Hour) }
	if _, err := readCachedIndex(repo); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired: %v", err)
	}
}

func TestCatalogEntryHashMismatch(t *testing.T) {
	stubModules(t)
	pub, priv := testCatalogKey(t)
	dir, repo := serveCatalog(t, pub)
	publishCatalog(t, dir, priv, demoPlugin)
	os.WriteFile(filepath.Join(dir, "modules", "demo-plugin.json"), []byte(`{"name":"demo-plugin"}`), 0644)
	if _, err := refreshRepo(repo); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("hash mismatch: %v", err)
	}
}

func TestPluginInstallSecretsSettingsArtifactsUpgrade(t *testing.T) {
	root, installed, _ := stubModules(t)
	moduleDirRoot = root
	defer func() { moduleDirRoot = "" }()
	moduleExec = func(c ModuleCmd) (string, error) { return c.Expect, nil }
	defer func() { moduleExec = runModuleCmd }()
	bin := []byte("#!/bin/sh\necho hi\n")
	artifactDownload = func(u, dst string, max int64) (string, error) { return sha256Hex(bin), os.WriteFile(dst, bin, 0600) }
	defer func() { artifactDownload = catalogDownload }()

	v1 := ModuleManifest{Name: "s3", Version: "1", Packages: []string{"garage", "old-tool"},
		Settings:  []Setting{{Name: "capacity", Default: "10G", Pattern: `^[0-9]+[MGT]$`}},
		Secrets:   map[string]string{"rpc": "hex:32"},
		Artifacts: []ModuleArtifact{{URL: "https://example.com/setup", SHA256: sha256Hex(bin), Path: "/var/lib/ziro/plugins/s3/setup", Mode: "0755"}},
		Files:     []ModuleFile{{Path: "/etc/garage.toml", Mode: "0600", Content: "rpc_secret = \"{{secret.rpc}}\"\ncap = {{setting.capacity}}\n"}},
		Services: []ModuleService{{Name: "garage", Exec: "/usr/bin/garage", Args: "server", User: "garage", EnvFile: "/etc/garage.env",
			PIDFile: "/run/ziro-garage.pid", LogFile: "/var/log/garage.log"}, {Name: "old-helper", Exec: "/usr/bin/h", PIDFile: "/run/h.pid", LogFile: "/var/log/h.log"}}}
	if err := v1.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := installModule(v1, moduleOpts{Set: map[string]string{"capacity": "50G"}}); err != nil {
		t.Fatal(err)
	}
	cfg, _ := os.ReadFile(filepath.Join(root, "etc/garage.toml"))
	secrets, _ := loadOrCreateSecrets(moduleSecretsPath("s3"), v1.Secrets, nil)
	if !strings.Contains(string(cfg), secrets["rpc"]) || !strings.Contains(string(cfg), "cap = 50G") {
		t.Fatalf("config %s", cfg)
	}
	if fi, _ := os.Stat(moduleSecretsPath("s3")); fi.Mode().Perm() != 0600 {
		t.Fatal("secrets file not 0600")
	}
	if snap, _ := os.ReadFile(manifestSnapshotPath("s3")); strings.Contains(string(snap), secrets["rpc"]) {
		t.Fatal("secret leaked into the manifest snapshot")
	}
	conf, _ := os.ReadFile(filepath.Join(servicesDir, "garage.conf"))
	if !strings.Contains(string(conf), "user=garage\n") || !strings.Contains(string(conf), "env_file=/etc/garage.env\n") {
		t.Fatalf("service conf %s", conf)
	}
	art := filepath.Join(root, "var/lib/ziro/plugins/s3/setup")
	if fi, err := os.Stat(art); err != nil || fi.Mode().Perm() != 0755 {
		t.Fatalf("artifact: %v", err)
	}

	// v2 drops old-tool, old-helper and the artifact; settings and secrets survive the upgrade.
	v2 := v1
	v2.Version, v2.Packages, v2.Artifacts = "2", []string{"garage"}, nil
	v2.Services = v1.Services[:1]
	old, _ := loadModuleState("s3")
	if err := installModule(v2, moduleOpts{}); err != nil {
		t.Fatal(err)
	}
	removeFootprint("s3", old, v2)
	cfg, _ = os.ReadFile(filepath.Join(root, "etc/garage.toml"))
	if !strings.Contains(string(cfg), "cap = 50G") || !strings.Contains(string(cfg), secrets["rpc"]) {
		t.Fatalf("upgrade lost settings/secrets: %s", cfg)
	}
	if installed["old-tool"] || !installed["garage"] || fileExists(art) || fileExists(filepath.Join(servicesDir, "old-helper.conf")) {
		t.Fatalf("upgrade left old footprint: pkgs=%v", installed)
	}
	st, _ := loadModuleState("s3")
	undoModule(v2, st)
	if installed["garage"] || fileExists(moduleSecretsPath("s3")) || fileExists(manifestSnapshotPath("s3")) {
		t.Fatal("disable left secrets, snapshot or packages")
	}
}

func TestBackupRemoteValidation(t *testing.T) {
	for _, ok := range []string{"ziro-s3:ziro-backups", "s3:bucket/host-1/", "r:"} {
		if checkRemote(ok) != nil {
			t.Errorf("rejected %q", ok)
		}
	}
	for _, bad := range []string{"--config=/x:y", "/etc/passwd", "r:../x", "r:a b", "r:x;rm", ":x"} {
		if checkRemote(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestOfficialReposValid(t *testing.T) {
	for _, r := range officialRepos {
		if err := r.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInputSecrets(t *testing.T) {
	specs := map[string]string{"DB_PASSWORD": "alnum:24", "API_KEY": "input", "EXTRA": "input?"}
	if _, _, err := fillSecrets(nil, specs, nil); err == nil || !strings.Contains(err.Error(), "API_KEY is required") {
		t.Fatalf("missing required input: %v", err)
	}
	got, changed, err := fillSecrets(nil, specs, map[string]string{"API_KEY": "sk-1"})
	if err != nil || !changed || got["API_KEY"] != "sk-1" || len(got["DB_PASSWORD"]) != 24 || got["EXTRA"] != "" {
		t.Fatalf("first fill %v %v %v", got, changed, err)
	}
	// Redeploy without --secret keeps both; a new value replaces only the input.
	again, changed, _ := fillSecrets(got, specs, nil)
	if changed || again["API_KEY"] != "sk-1" || again["DB_PASSWORD"] != got["DB_PASSWORD"] {
		t.Errorf("redeploy changed secrets: %v", again)
	}
	rot, changed, _ := fillSecrets(got, specs, map[string]string{"API_KEY": "sk-2"})
	if !changed || rot["API_KEY"] != "sk-2" || rot["DB_PASSWORD"] != got["DB_PASSWORD"] {
		t.Errorf("rotation: %v", rot)
	}
	for _, bad := range []map[string]string{{"DB_PASSWORD": "x"}, {"NOPE": "x"}, {"API_KEY": "a\nB=c"}} {
		if _, _, err := fillSecrets(got, specs, bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "key"), []byte("sk-file\n"), 0600)
	t.Setenv("API_KEY", "sk-env")
	vals, err := parseSecretFlags([]string{"A=" + "@" + filepath.Join(dir, "key"), "API_KEY", "C=lit=eral"})
	if err != nil || vals["A"] != "sk-file" || vals["API_KEY"] != "sk-env" || vals["C"] != "lit=eral" {
		t.Fatalf("parseSecretFlags %v %v", vals, err)
	}
	if _, err := parseSecretFlags([]string{"bad-key=x"}); err == nil {
		t.Error("bad key accepted")
	}
}

func TestDataDirOwner(t *testing.T) {
	old := appDataRoot
	appDataRoot = t.TempDir()
	defer func() { appDataRoot = old }()
	a := Assignment{App: "claw", Data: []string{"/home/node/.openclaw"}, DataUID: os.Getuid()}
	if os.Getuid() != 0 {
		a.DataUID = 0 // chown to another uid needs root; the ownership itself is checked on hosts
	}
	if err := ensureDataDirs(a); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dataDir("claw", 0, "/home/node/.openclaw")); err != nil || fi.Mode().Perm() != 0700 {
		t.Fatalf("data dir %v %v", fi, err)
	}
	if ensureDataDirs(Assignment{App: "claw", Data: []string{"/x"}, DataUID: 70000}) == nil {
		t.Error("out-of-range data_uid accepted")
	}
}
