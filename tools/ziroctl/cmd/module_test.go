package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedManifestsValid(t *testing.T) {
	all, err := loadManifests()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"clamav", "auditd", "security"} {
		if _, ok := all[n]; !ok {
			t.Fatalf("module %s missing", n)
		}
	}
	for n := range all {
		if _, err := enableOrder(all, n); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	order, _ := enableOrder(all, "security")
	if strings.Join(order, ",") != "clamav,auditd,security" {
		t.Fatalf("security enable order %v", order)
	}
	// clamd must never listen on the network.
	for _, f := range all["clamav"].Files {
		if strings.Contains(f.Content, "TCPSocket") || strings.Contains(f.Content, "TCPAddr") {
			t.Fatalf("%s opens a TCP listener", f.Path)
		}
	}
}

func TestManifestValidationRejectsUnsafe(t *testing.T) {
	for _, m := range []ModuleManifest{
		{Name: "../x"},
		{Name: "a", Files: []ModuleFile{{Path: "etc/x", Mode: "0644"}}},
		{Name: "a", Files: []ModuleFile{{Path: "/etc/../x", Mode: "0644"}}},
		{Name: "a", Prepare: []ModuleCmd{{Exec: "sh"}}},
		{Name: "a", Services: []ModuleService{{Name: "s", Exec: "/bin/x", PIDFile: "/etc/p", LogFile: "/var/log/s"}}},
		{Name: "a", Cron: []string{"* * * * * x\n* * * * * y"}},
	} {
		if err := m.validate(); err == nil {
			t.Errorf("accepted %+v", m)
		}
	}
	if _, err := enableOrder(map[string]ModuleManifest{"a": {Name: "a", Requires: []string{"b"}}, "b": {Name: "b", Requires: []string{"a"}}}, "a"); err == nil {
		t.Fatal("dependency cycle not detected")
	}
}

// stubModules redirects every path and system call a module touches into a temp dir.
func stubModules(t *testing.T) (root string, installed map[string]bool, started *[]string) {
	root = t.TempDir()
	moduleStateDir = filepath.Join(root, "modules")
	catalogDir = filepath.Join(root, "catalog")
	reposPath = filepath.Join(root, "repos.json")
	servicesDir = filepath.Join(root, "services")
	cronPath = filepath.Join(root, "crontab")
	alertConfigPath = filepath.Join(root, "alerting.json")
	alertSpoolDir = filepath.Join(root, "alerts")
	clusterDir = root
	os.MkdirAll(servicesDir, 0755)
	installed = map[string]bool{"shared-pkg": true}
	var s []string
	started = &s
	apkInstalled = func(p string) bool { return installed[p] }
	apkAdd = func(p []string) error {
		for _, x := range p {
			installed[x] = true
		}
		return nil
	}
	apkDel = func(p []string) error {
		for _, x := range p {
			delete(installed, x)
		}
		return nil
	}
	memTotalMB = func() int { return 4096 }
	startModuleService = func(n string) error { *started = append(*started, n); return nil }
	stopModuleService = func(n string) error { return nil }
	return root, installed, started
}

func TestModuleEnableDisableRoundTrip(t *testing.T) {
	root, installed, started := stubModules(t)
	cfg := filepath.Join(root, "etc", "x.conf")
	os.MkdirAll(filepath.Dir(cfg), 0755)
	os.WriteFile(cfg, []byte("package default\n"), 0644) // shipped by the package
	os.WriteFile(cronPath, []byte("0 * * * * /usr/bin/ziroctl service rotate-logs\n"), 0600)
	m := ModuleManifest{Name: "demo", Version: "1", Packages: []string{"demo-pkg", "shared-pkg"},
		Files:    []ModuleFile{{Path: cfg, Mode: "0644", Content: "managed\n"}},
		Cron:     []string{"30 3 * * * /usr/bin/ziroctl security scan --av --quiet"},
		Services: []ModuleService{{Name: "demod", Exec: "/usr/sbin/demod", PIDFile: "/run/ziro-demod.pid", LogFile: "/var/log/demod.log"}}}
	if err := installModule(m, moduleOpts{}); err != nil {
		t.Fatal(err)
	}
	st, _ := loadModuleState("demo")
	if st.Status != "enabled" || strings.Join(st.Packages, ",") != "demo-pkg" || len(*started) != 1 {
		t.Fatalf("state %+v started %v (shared-pkg was already installed and must not be claimed)", st, *started)
	}
	if b, _ := os.ReadFile(cfg); string(b) != "managed\n" {
		t.Fatal("config not written")
	}
	if b, _ := os.ReadFile(cfg + ".ziro-orig"); string(b) != "package default\n" {
		t.Fatal("package default not preserved")
	}
	conf, _ := os.ReadFile(filepath.Join(servicesDir, "demod.conf"))
	if !strings.Contains(string(conf), "restart=always") {
		t.Fatalf("service conf %s", conf)
	}
	cron, _ := os.ReadFile(cronPath)
	if !strings.Contains(string(cron), "rotate-logs") || !strings.Contains(string(cron), cronMarker+"demo\n30 3") {
		t.Fatalf("cron %s", cron)
	}
	// Re-enabling is idempotent (no duplicate cron lines).
	if err := installModule(m, moduleOpts{}); err != nil {
		t.Fatal(err)
	}
	if cron, _ := os.ReadFile(cronPath); strings.Count(string(cron), "security scan --av") != 1 {
		t.Fatalf("cron duplicated: %s", cron)
	}

	// disable: embedded manifests don't know "demo", so drive it through a stub manifest set.
	st, _ = loadModuleState("demo")
	undoModule(m, st)
	if installed["demo-pkg"] || !installed["shared-pkg"] {
		t.Fatalf("packages after disable: %v", installed)
	}
	if b, _ := os.ReadFile(cfg); string(b) != "package default\n" {
		t.Fatalf("package default not restored: %q", b)
	}
	if fileExists(filepath.Join(servicesDir, "demod.conf")) || fileExists(moduleStatePath("demo")) {
		t.Fatal("service conf or state left behind")
	}
	if cron, _ := os.ReadFile(cronPath); strings.Contains(string(cron), "demo") || !strings.Contains(string(cron), "rotate-logs") {
		t.Fatalf("cron after disable: %s", cron)
	}
}

func TestModuleKeepsAdminEdits(t *testing.T) {
	root, _, _ := stubModules(t)
	cfg := filepath.Join(root, "x.conf")
	m := ModuleManifest{Name: "demo", Version: "1", Files: []ModuleFile{{Path: cfg, Mode: "0644", Content: "v1\n"}}}
	if err := installModule(m, moduleOpts{}); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(cfg, []byte("admin tuned\n"), 0644)
	m.Files[0].Content = "v2\n"
	if err := installModule(m, moduleOpts{}); err != nil { // e.g. reinstall after an upgrade
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(cfg); string(b) != "admin tuned\n" {
		t.Fatal("admin edit overwritten")
	}
	st, _ := loadModuleState("demo")
	undoModule(m, st)
	if b, _ := os.ReadFile(cfg); string(b) != "admin tuned\n" {
		t.Fatal("admin-edited file removed on disable")
	}
}

func TestModuleMemoryGate(t *testing.T) {
	stubModules(t)
	memTotalMB = func() int { return 1024 }
	m := ModuleManifest{Name: "big", Version: "1", MinMemoryMB: 1536}
	if err := installModule(m, moduleOpts{}); err == nil || !strings.Contains(err.Error(), "1536 MB") {
		t.Fatalf("memory gate: %v", err)
	}
	if err := installModule(m, moduleOpts{Force: true}); err != nil {
		t.Fatalf("--force: %v", err)
	}
}

func TestParseClamdscan(t *testing.T) {
	out := "/tmp/eicar.com: Win.Test.EICAR_HC-1 FOUND\n/root/a b.txt: Eicar-Signature FOUND\nclean line\n/x: OK\n"
	f := parseClamdscan(out)
	if len(f) != 2 || f[0].Signature != "Win.Test.EICAR_HC-1" || f[1].Path != "/root/a b.txt" {
		t.Fatalf("%+v", f)
	}
}

// The security pack enables its dependencies as "auto"; disabling the pack removes them unless the
// admin enabled one explicitly.
func TestSecurityPackAutoDependencies(t *testing.T) {
	_, installed, _ := stubModules(t)
	moduleExec = func(c ModuleCmd) (string, error) { return c.Expect, nil } // health "expect" is satisfied
	defer func() { moduleExec = runModuleCmd }()
	moduleChown = func(string, string) error { return nil } // the clamav user doesn't exist here
	defer func() { moduleChown = chownSpec }()
	moduleDirRoot = t.TempDir()
	defer func() { moduleDirRoot = "" }()

	if err := enableModule("security", moduleOpts{}); err != nil {
		t.Fatal(err)
	}
	en := enabledModules()
	if en["security"] == nil || en["security"].Auto || !en["clamav"].Auto || !en["auditd"].Auto || !installed["audit"] {
		t.Fatalf("after enable: %+v", en)
	}
	if err := disableModule("clamav"); err == nil || !strings.Contains(err.Error(), "required by security") {
		t.Fatalf("disabling a dependency of an enabled pack must be refused: %v", err)
	}
	// The admin also enables auditd explicitly: it must survive disabling the pack.
	if err := enableModule("auditd", moduleOpts{}); err != nil {
		t.Fatal(err)
	}
	if err := disableModule("security"); err != nil {
		t.Fatal(err)
	}
	en = enabledModules()
	if en["security"] != nil || en["clamav"] != nil || en["auditd"] == nil || installed["freshclam"] || !installed["audit"] {
		t.Fatalf("after disabling the pack: %+v installed=%v", en, installed)
	}
}
