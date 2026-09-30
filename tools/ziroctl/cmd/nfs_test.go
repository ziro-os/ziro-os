package cmd

import (
	"strings"
	"testing"
)

func TestRenderExports(t *testing.T) {
	s, err := renderExports([]NFSExport{{Path: "/srv/media", Clients: []string{"10.0.0.7", "10.0.1.0/24"}, ReadOnly: true}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "/srv/media 10.0.0.7/32(ro,sync,no_subtree_check,root_squash,sec=sys,fsid=") ||
		!strings.Contains(s, " 10.0.1.0/24(ro,") || strings.Contains(s, "no_root_squash") {
		t.Fatalf("exports:\n%s", s)
	}
	for _, bad := range []NFSExport{
		{Path: "/etc", Clients: []string{"10.0.0.0/8"}},
		{Path: "/var/lib/ziro", Clients: []string{"10.0.0.0/8"}},
		{Path: "/root/x", Clients: []string{"10.0.0.0/8"}},
		{Path: "relative", Clients: []string{"10.0.0.0/8"}},
		{Path: "/srv/a b", Clients: []string{"10.0.0.0/8"}},
		{Path: "/srv/x", Clients: []string{"0.0.0.0/0"}}, // everyone
		{Path: "/srv/x", Clients: []string{"*"}},
		{Path: "/srv/x", Clients: []string{"2001:db8::/32"}},
		{Path: "/srv/x"},
	} {
		if _, err := renderExports([]NFSExport{bad}); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if o := nfsMountOptions("10.200.0.1", true); !strings.Contains(o, "vers=4.2") || !strings.Contains(o, "nosuid") || !strings.HasSuffix(o, ",ro") {
		t.Fatal(o)
	}
}

func TestParseVolume(t *testing.T) {
	s, tg, ro, err := parseVolume("media:/usr/share/nginx/html:ro")
	if err != nil || s != "media" || tg != "/usr/share/nginx/html" || !ro {
		t.Fatalf("%s %s %v %v", s, tg, ro, err)
	}
	for _, bad := range []string{"media", "media:rel", "media:/", "Media:/x", "../x:/y", "m:/x:rw", "m:/a/../b"} {
		if _, _, _, err := parseVolume(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := validateVolumes(&ClusteredApp{Volumes: []string{"a:/data", "b:/data"}}); err == nil {
		t.Error("two volumes on one path accepted")
	}
}

func storageState() *ClusterState {
	return &ClusterState{PolicyDefault: "deny",
		Nodes: []ClusterNode{{ID: "m", MeshIP: "10.200.0.1", Status: "Ready"}, {ID: "s", MeshIP: "10.200.0.2", Status: "Ready"},
			{ID: "w", MeshIP: "10.200.0.3", Status: "Ready"}},
		Shares:   []ClusterShare{{Name: "media", Node: "s", Standby: "m"}},
		Apps:     []ClusteredApp{{Name: "web", Image: "nginx", Replicas: 2, Volumes: []string{"media:/html:ro"}}, {Name: "api", Image: "x", Replicas: 1}},
		Replicas: []Replica{{App: "web", Index: 0, Node: "m"}, {App: "web", Index: 1, Node: "w"}, {App: "api", Index: 0, Node: "s"}},
	}
}

func TestStorageFor(t *testing.T) {
	st := storageState()
	ex, mo := storageFor(st, "s")
	if len(ex) != 1 || strings.Join(ex[0].Clients, ",") != "10.200.0.1,10.200.0.3" || ex[0].Path != storageRoot+"/media" || len(mo) != 0 {
		t.Fatalf("storage node: %+v %+v", ex, mo)
	}
	ex, mo = storageFor(st, "w")
	if len(ex) != 0 || len(mo) != 1 || mo[0].Server != "10.200.0.2" {
		t.Fatalf("consumer: %+v %+v", ex, mo)
	}
	r := storagePolicyRule(st, "s")
	if r == nil || r.Port != 2049 || strings.Join(r.Sources, ",") != "10.200.0.1,10.200.0.3" {
		t.Fatalf("policy rule %+v", r)
	}
	if storagePolicyRule(st, "w") != nil {
		t.Fatal("a consumer node must not open 2049")
	}
	if args := volumeArgs(st.Apps[0].Volumes); len(args) != 1 || args[0] != volumeRoot+"/media:/html:ro" {
		t.Fatalf("volume args %v", args)
	}
}

func TestHoldBackUnmountedShares(t *testing.T) {
	as := []Assignment{{Name: "a", Volumes: []string{volumeRoot + "/media:/html:ro"}}, {Name: "b"}}
	if got := holdBack(as, map[string]bool{"media": true}); len(got) != 1 || got[0].Name != "b" {
		t.Fatalf("replica on an unmounted share started: %+v", got)
	}
	if got := holdBack(as, nil); len(got) != 2 {
		t.Fatal("nothing to hold back")
	}
}

func TestStorageFailoverRollsConsumers(t *testing.T) {
	st := storageState()
	before := specHash(*st.app("web"))
	a := *st.app("web")
	a.VolumeEpoch++
	if specHash(a) == before {
		t.Fatal("a failover must change the consumers' spec hash (rolling restart)")
	}
	if specHash(*st.app("api")) != specHash(ClusteredApp{Name: "api", Image: "x", Replicas: 1}) {
		t.Fatal("apps without volumes keep their hash")
	}
}
