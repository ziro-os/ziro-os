package cmd

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestStickyData(t *testing.T) {
	yes, no := true, false
	for name, c := range map[string]struct {
		app  ClusteredApp
		want bool
	}{
		"no data":               {ClusteredApp{Replicas: 1}, false},
		"single database":       {ClusteredApp{Replicas: 1, Data: []string{"/d"}}, true},
		"stopped database":      {ClusteredApp{Replicas: 0, Data: []string{"/d"}}, true},
		"several unreplicated":  {ClusteredApp{Replicas: 3, Data: []string{"/d"}}, false},
		"replicated":            {ClusteredApp{Replicas: 1, Data: []string{"/d"}, Replicated: true}, false},
		"explicitly sticky":     {ClusteredApp{Replicas: 3, Data: []string{"/d"}, Sticky: &yes}, true},
		"explicitly not sticky": {ClusteredApp{Replicas: 1, Data: []string{"/d"}, Sticky: &no}, false},
		"sticky without data":   {ClusteredApp{Replicas: 1, Sticky: &yes}, false},
	} {
		if got := c.app.stickyData(); got != c.want {
			t.Errorf("%s: sticky = %v", name, got)
		}
	}
}

// A database on a node that dies must wait for that node: a replica rescheduled elsewhere would
// start with an empty data directory.
func TestStickyReplicaStaysOnItsNode(t *testing.T) {
	now := time.Now()
	st := &ClusterState{
		Nodes: testNodes(now, "a", "b"),
		Apps: []ClusteredApp{
			{Name: "db", Image: "pg", Replicas: 1, Data: []string{"/data"}},
			{Name: "web", Image: "nginx", Replicas: 2},
		},
	}
	scheduleReplicas(st, now)
	var dbNode string
	for _, r := range st.Replicas {
		if r.App == "db" {
			dbNode = r.Node
		}
	}
	if dbNode == "" {
		t.Fatal("the database must be placed")
	}

	// Its node stops heartbeating, well past the timeout and the point where workers are removed.
	for i := range st.Nodes {
		if st.Nodes[i].ID == dbNode {
			st.Nodes[i].LastSeen = now.Add(-10 * nodeGCAfter)
			st.Nodes[i].Role = "worker"
		}
	}
	later := now.Add(time.Minute)
	scheduleReplicas(st, later)
	for _, r := range st.Replicas {
		if r.App == "db" {
			if r.Node != dbNode || !strings.HasPrefix(r.Error, stickyDownPrefix) {
				t.Fatalf("a sticky replica must wait for its node: %+v", r)
			}
		}
	}
	if st.node(dbNode) == nil {
		t.Fatal("a node holding sticky data must not be garbage collected")
	}
	// A stateless app on the same node does move.
	for _, r := range st.Replicas {
		if r.App == "web" && r.Node == dbNode {
			t.Fatalf("stateless replica stayed on the dead node: %+v", r)
		}
	}

	// The node returns and the replica runs: the message goes away.
	for i := range st.Nodes {
		if st.Nodes[i].ID == dbNode {
			st.Nodes[i].LastSeen = later
		}
	}
	scheduleReplicas(st, later)
	for _, r := range st.Replicas {
		if r.App == "db" && (r.Node != dbNode || r.Error != "") {
			t.Fatalf("after the node returned: %+v", r)
		}
	}

	// A start that keeps failing is not moved either: another node has none of the data.
	for i := range st.Replicas {
		if st.Replicas[i].App == "db" {
			st.Replicas[i].Fails, st.Replicas[i].Error = maxReplicaFails, "exit status 1: boom"
		}
	}
	scheduleReplicas(st, later)
	for _, r := range st.Replicas {
		if r.App == "db" && r.Node != dbNode {
			t.Fatalf("a failing sticky replica moved: %+v", r)
		}
	}

	// Opting out restores the old behavior: the replica moves.
	no := false
	st.Apps[0].Sticky = &no
	for i := range st.Nodes {
		if st.Nodes[i].ID == dbNode {
			st.Nodes[i].LastSeen = now.Add(-10 * nodeGCAfter)
		}
	}
	scheduleReplicas(st, later.Add(time.Minute))
	for _, r := range st.Replicas {
		if r.App == "db" && r.Node == dbNode {
			t.Fatalf("sticky: false must let the replica move: %+v", r)
		}
	}
}

func TestStickyReplicaIsNotRebalanced(t *testing.T) {
	now := time.Now()
	st := &ClusterState{
		Nodes: testNodes(now, "a", "b"),
		Apps:  []ClusteredApp{{Name: "db", Image: "pg", Replicas: 2, Data: []string{"/d"}, Sticky: boolPtr(true)}},
	}
	scheduleReplicas(st, now)
	// Both replicas end up on the idle node pair; add a node and make everything look settled.
	st.Nodes = append(st.Nodes, ClusterNode{ID: "c", LastSeen: now})
	for i := range st.Replicas {
		st.Replicas[i].Node = "a"
	}
	for i := range st.Nodes {
		st.Nodes[i].Running = nil
		for _, r := range st.Replicas {
			if r.Node == st.Nodes[i].ID {
				st.Nodes[i].Running = append(st.Nodes[i].Running, replicaName(r.App, r.Index, specHash(st.Apps[0])))
			}
		}
	}
	scheduleReplicas(st, now)
	for _, r := range st.Replicas {
		if r.Node != "a" {
			t.Fatalf("a sticky replica was rebalanced: %+v", r)
		}
	}
}

func boolPtr(b bool) *bool { return &b }

func TestDrainRefusesStickyData(t *testing.T) {
	stubApps(t)
	if err := saveClusterConfig(&ClusterConfig{ClusterID: "c", Role: "master", NodeID: "m1"}); err != nil {
		t.Fatal(err)
	}
	if err := withState(func(st *ClusterState) error {
		st.Nodes = []ClusterNode{{ID: "m1", Role: "master", LastSeen: time.Now()}, {ID: "w1", Role: "worker", LastSeen: time.Now()}}
		st.Apps = []ClusteredApp{{Name: "db", Image: "pg", Replicas: 1, Data: []string{"/d"}}, {Name: "web", Image: "n", Replicas: 1}}
		st.Replicas = []Replica{{App: "db", Index: 1, Node: "w1"}, {App: "web", Index: 1, Node: "w1"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := clusterNodeAction("w1", "drain"); err == nil || !strings.Contains(err.Error(), "db/1") || !strings.Contains(err.Error(), "--force-move") {
		t.Fatalf("drain of a node holding data: %v", err)
	}
	if st, _ := readState(); st.Replicas[0].Node != "w1" || st.node("w1").Cordoned {
		t.Fatal("a refused drain must change nothing")
	}
	if err := clusterNodeAction("w1", "force-drain"); err != nil {
		t.Fatal(err)
	}
	if st, _ := readState(); st.Replicas[0].Node == "w1" || st.Replicas[1].Node == "w1" || !st.node("w1").Cordoned {
		t.Fatalf("force-drain: %+v", st.Replicas)
	}
}

func TestStopTimeout(t *testing.T) {
	db := ClusteredApp{Name: "db", Data: []string{"/d"}}
	if db.stopTimeout() != dataStopTimeout || (ClusteredApp{Name: "web"}).stopTimeout() != 0 || (ClusteredApp{StopTimeout: 90}).stopTimeout() != 90 {
		t.Fatal("stop timeout defaults")
	}
	// Defaults do not roll running apps; an explicit value is part of the spec.
	if specHash(db) != specHash(ClusteredApp{Name: "db", Data: []string{"/d"}}) {
		t.Fatal("hash must be stable")
	}
	if specHash(ClusteredApp{Name: "x", StopTimeout: 60}) == specHash(ClusteredApp{Name: "x"}) {
		t.Fatal("an explicit stop timeout must be in the spec hash")
	}
	if err := validateApp(&ClusteredApp{Name: "x", Image: "i", StopTimeout: 601}, nil); err == nil {
		t.Fatal("stop_timeout above the limit accepted")
	}

	a := Assignment{Name: "zc-db-1-h", App: "db", Image: "pg", StopTimeout: 30}
	if args := strings.Join(containerArgs(a), " "); !strings.Contains(args, "--label "+stopTimeoutLabel+"=30") {
		t.Fatalf("the container must carry its stop timeout: %s", args)
	}
	if args := strings.Join(containerArgs(Assignment{Name: "n", App: "web", Image: "i"}), " "); strings.Contains(args, stopTimeoutLabel) {
		t.Fatalf("no label without a timeout: %s", args)
	}
	if got := removeSteps("c", 30); !slices.Equal(got[0], []string{"stop", "-t", "30", "c"}) || !slices.Equal(got[1], []string{"rm", "-f", "c"}) || len(got) != 2 {
		t.Fatalf("graceful removal: %v", got)
	}
	if got := removeSteps("c", 0); len(got) != 1 || !slices.Equal(got[0], []string{"rm", "-f", "c"}) {
		t.Fatalf("immediate removal: %v", got)
	}
	st := &ClusterState{Nodes: []ClusterNode{{ID: "n", LastSeen: time.Now()}}, Apps: []ClusteredApp{db},
		Replicas: []Replica{{App: "db", Index: 1, Node: "n"}}}
	st.Apps[0].Replicas, st.Apps[0].Image = 1, "pg"
	if as := assignmentsFor(st, "n", nil); len(as) != 1 || as[0].StopTimeout != dataStopTimeout {
		t.Fatalf("assignments carry the default: %+v", as)
	}
}

func TestFailedDeployRemovesWhatItCreated(t *testing.T) {
	scaleTestCluster(t)
	d := replicatedDef()
	d.Components = append(d.Components, AppComponent{Name: "proxy", Port: 80, Env: map[string]string{"X": "{{setting.missing}}"}})
	d.Versions["8.4"] = AppVersion{Images: map[string]string{"mysql": "docker.io/library/mysql:8.4" + testDigest, "proxy": "docker.io/library/nginx:1" + testDigest}}
	err := deployAppDef(d, "8.4", appDeployOpts{Name: "mc"})
	if err == nil {
		t.Fatal("the second component cannot be rendered, the deploy must fail")
	}
	if st, _ := readState(); st.app("mc-mysql") != nil || st.app("mc") != nil {
		t.Fatalf("a failed deploy left cluster apps behind: %+v", st.Apps)
	}
}
