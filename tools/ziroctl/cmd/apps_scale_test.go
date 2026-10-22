package cmd

import (
	"strings"
	"testing"
)

func scaleTestCluster(t *testing.T) {
	t.Helper()
	stubApps(t)
	if err := saveClusterConfig(&ClusterConfig{ClusterID: "c", Role: "master", NodeID: "m1"}); err != nil {
		t.Fatal(err)
	}
	_ = withState(func(st *ClusterState) error {
		st.Nodes = []ClusterNode{{ID: "m1", Role: "master"}}
		return nil
	})
}

func replicatedDef() AppDef {
	return AppDef{Schema: 1, Name: "mysql-cluster", Default: "8.4", Cluster: true,
		Versions: map[string]AppVersion{"8.4": {Images: map[string]string{"mysql": "docker.io/library/mysql:8.4" + testDigest}}},
		Components: []AppComponent{{Name: "mysql", Replicas: 3, MaxReplicas: 9, Port: 3306,
			Data: []string{"/var/lib/mysql"}, Args: []string{"bash", "-c", "exec mysqld"}}}}
}

func TestAppScale(t *testing.T) {
	scaleTestCluster(t)
	d := replicatedDef()
	in := &AppInstance{Name: "mc", App: d.Name, Version: "8.4", Mode: "cluster", Def: d}
	if err := deployAppCluster(in, appDeployOpts{}); err != nil {
		t.Fatal(err)
	}
	if err := saveAppInstance(in); err != nil {
		t.Fatal(err)
	}
	st, _ := readState()
	if a := st.app("mc"); a == nil || !a.Replicated || a.Replicas != 3 {
		t.Fatalf("a replicating app is marked replicated: %+v", a)
	}

	if err := appScale("mc", 5, ""); err != nil {
		t.Fatal(err)
	}
	st, _ = readState()
	a := st.app("mc")
	if a.Replicas != 5 || strings.Count(a.Env["ZIRO_PEERS"], "cluster.ziro") != 5 || !a.Replicated {
		t.Fatalf("scaled app: %+v", a)
	}
	if got, _ := loadAppInstance("mc"); got.Replicas["mysql"] != 5 {
		t.Fatalf("the scale is remembered: %v", got.Replicas)
	}
	for _, c := range []struct {
		n    int
		comp string
		want string
	}{
		{10, "", "at most 9"},
		{0, "", "at least 1"},
		{4, "web", `no component "web"`},
	} {
		if err := appScale("mc", c.n, c.comp); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("scale %d %q: %v, want %q", c.n, c.comp, err, c.want)
		}
	}

	// A redeploy without --replicas keeps the scale; a remembered scale the new definition no
	// longer allows falls back to the definition's.
	got, _ := loadAppInstance("mc")
	if err := deployAppCluster(got, appDeployOpts{prevReplicas: map[string]int{"mysql": 5}}); err != nil {
		t.Fatal(err)
	}
	if st, _ = readState(); st.app("mc").Replicas != 5 {
		t.Fatalf("redeploy reset the scale to %d", st.app("mc").Replicas)
	}
	if err := deployAppCluster(got, appDeployOpts{prevReplicas: map[string]int{"mysql": 50}}); err != nil {
		t.Fatal(err)
	}
	if st, _ = readState(); st.app("mc").Replicas != 3 {
		t.Fatalf("a scale above max_replicas must fall back: %d", st.app("mc").Replicas)
	}
}

func TestAppScaleRefusals(t *testing.T) {
	scaleTestCluster(t)
	pg := testPostgresDef()
	settings, err := resolveSettings(pg.Settings, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	in := &AppInstance{Name: "postgres", App: "postgres", Version: "17", Mode: "cluster", Def: pg, Settings: settings}
	if err := deployAppCluster(in, appDeployOpts{}); err != nil {
		t.Fatal(err)
	}
	if err := saveAppInstance(in); err != nil {
		t.Fatal(err)
	}
	if err := appScale("postgres", 2, ""); err == nil || !strings.Contains(err.Error(), "does not replicate") {
		t.Fatalf("a single-instance database is not scaled: %v", err)
	}
	if err := appScale("nope", 2, ""); err == nil {
		t.Fatal("unknown app")
	}
	local := &AppInstance{Name: "loc", App: "postgres", Version: "17", Mode: "local", Def: pg}
	if err := saveAppInstance(local); err != nil {
		t.Fatal(err)
	}
	if err := appScale("loc", 2, ""); err == nil || !strings.Contains(err.Error(), "needs a cluster") {
		t.Fatalf("local app: %v", err)
	}
	// The generic path refuses too, and says what to do.
	if err := clusterScale("postgres", 2); err == nil || !strings.Contains(err.Error(), "independent, empty copy") {
		t.Fatalf("cluster scale of a database: %v", err)
	}
	if st, _ := readState(); st.app("postgres").Replicas != 1 {
		t.Fatal("a refused scale must change nothing")
	}
	if err := clusterScaleApp("postgres", 2, true); err != nil {
		t.Fatalf("--force: %v", err)
	}
}

func TestScaleRefusal(t *testing.T) {
	data := ClusteredApp{Name: "db", Replicas: 1, Data: []string{"/data"}}
	for name, c := range map[string]struct {
		app  ClusteredApp
		n    int
		want bool
	}{
		"database from one to two":   {data, 2, true},
		"database from zero to two":  {ClusteredApp{Name: "db", Data: []string{"/data"}}, 2, true},
		"same count":                 {data, 1, false},
		"scale down":                 {ClusteredApp{Name: "db", Replicas: 3, Data: []string{"/data"}}, 1, false},
		"already several, set up so": {ClusteredApp{Name: "db", Replicas: 2, Data: []string{"/data"}}, 4, false},
		"replicated":                 {ClusteredApp{Name: "db", Replicas: 1, Data: []string{"/data"}, Replicated: true}, 3, false},
		"stateless":                  {ClusteredApp{Name: "web", Replicas: 1}, 10, false},
	} {
		if err := scaleRefusal(c.app, c.n); (err != nil) != c.want {
			t.Errorf("%s: %v", name, err)
		}
	}
}
