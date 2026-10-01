package cmd

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNFSExportIdentity(t *testing.T) {
	out, err := renderExports([]NFSExport{
		{Path: "/srv/a", Clients: []string{"10.0.0.0/24"}},
		{Path: "/srv/b", Clients: []string{"10.0.0.5"}, Squash: "all", Owner: "1000:1000"},
		{Path: "/srv/c", Clients: []string{"10.0.0.5"}, Squash: "none", ReadOnly: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/srv/a 10.0.0.0/24(rw,sync,no_subtree_check,root_squash,",
		"/srv/b 10.0.0.5/32(rw,sync,no_subtree_check,all_squash,anonuid=1000,anongid=1000,",
		"/srv/c 10.0.0.5/32(ro,sync,no_subtree_check,no_root_squash,"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	for _, bad := range []NFSExport{
		{Path: "/srv/x", Clients: []string{"10.0.0.5"}, Squash: "everyone"},
		{Path: "/srv/x", Clients: []string{"10.0.0.5"}, Owner: "0:0"},
		{Path: "/srv/x", Clients: []string{"10.0.0.5"}, Owner: "1000:1000,rw"},
		{Path: "/srv/x", Clients: []string{"10.0.0.5"}, Owner: "app"}, // must be numeric by now
	} {
		if _, err := renderExports([]NFSExport{bad}); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if o, err := resolveOwner("1000:1001"); err != nil || o != "1000:1001" {
		t.Fatal(o, err)
	}
}

func TestNFSClients(t *testing.T) {
	nfsdClientsDir = t.TempDir()
	defer func() { nfsdClientsDir = "/proc/fs/nfsd/clients" }()
	d := filepath.Join(nfsdClientsDir, "7")
	os.MkdirAll(d, 0755)
	os.WriteFile(filepath.Join(d, "info"), []byte("clientid: 0xdeadbeef\naddress: \"10.0.0.5:879\"\nstatus: confirmed\nname: \"Linux NFSv4.2 web-1\"\nminor version: 2\n"), 0644)
	os.WriteFile(filepath.Join(d, "states"), []byte("- 0x1: { type: open, access: rw }\n- 0x2: { type: open, access: r- }\n- 0x3: { type: deleg }\n"), 0644)
	cs, err := listNFSClients([]NFSExport{{Path: "/srv/a", Clients: []string{"10.0.0.0/24"}}, {Path: "/srv/b", Clients: []string{"192.168.1.0/24"}},
		{Path: "/srv/c", Clients: []string{"10.0.0.5"}}}) // a bare address, as `export add --clients` stores it
	if err != nil || len(cs) != 1 {
		t.Fatal(cs, err)
	}
	c := cs[0]
	if c.Address != "10.0.0.5:879" || c.Name != "Linux NFSv4.2 web-1" || c.MinorVersion != "2" || c.OpenFiles != 2 || !slices.Equal(c.Exports, []string{"/srv/a", "/srv/c"}) {
		t.Fatalf("%+v", c)
	}
}

func TestModulePurgeRemovesOnlyCreatedDirs(t *testing.T) {
	root, _, _ := stubModules(t)
	moduleDirRoot = root
	defer func() { moduleDirRoot = "" }()
	moduleChown = func(string, string) error { return nil }
	defer func() { moduleChown = chownSpec }()
	pre := filepath.Join(root, "var/lib/shared")
	os.MkdirAll(pre, 0755) // existed before the module: never purged
	m := ModuleManifest{Name: "demo", Version: "1", Dirs: []ModuleDir{{Path: "/var/lib/shared", Mode: "0755"}, {Path: "/var/lib/demo", Mode: "0750"}, {Path: "/var/lib/demo/db", Mode: "0750"}}}
	if err := installModule(m, moduleOpts{}); err != nil {
		t.Fatal(err)
	}
	st, _ := loadModuleState("demo")
	if len(st.CreatedDirs) != 2 {
		t.Fatalf("created dirs %v", st.CreatedDirs)
	}
	os.WriteFile(filepath.Join(root, "var/lib/demo/db/data"), []byte("x"), 0600)
	undoModule(m, st)
	purgeModuleData(m, st)
	if fileExists(filepath.Join(root, "var/lib/demo")) || !fileExists(pre) {
		t.Fatal("purge must remove the module's dirs and keep pre-existing ones")
	}
}

func TestAgentPurgesOnlyUnassignedApps(t *testing.T) {
	appDataRoot = t.TempDir()
	defer func() { appDataRoot = "/var/lib/ziro/apps" }()
	for _, a := range []string{"gone", "running"} {
		os.MkdirAll(filepath.Join(appDataRoot, a, "1"), 0700)
	}
	purgeAppData([]string{"gone", "running", "../etc", ""}, []Assignment{{App: "running"}})
	if fileExists(filepath.Join(appDataRoot, "gone")) || !fileExists(filepath.Join(appDataRoot, "running")) {
		t.Fatal("purge must remove unassigned apps only")
	}
	st := &ClusterState{}
	markPurge(st, "a")
	st.PurgeData["old"] = time.Now().Add(-8 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if got := purgeList(st, time.Now()); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("purge list %v (expired entries must not be sent)", got)
	}
	markPurge(st, "b")
	if _, ok := st.PurgeData["old"]; ok {
		t.Fatal("expired entry not dropped")
	}
}
