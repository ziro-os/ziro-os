package cmd

import (
	"strings"
	"testing"
	"time"
)

// markRunning makes every placed replica report as running on its node.
func markRunning(st *ClusterState) {
	for i := range st.Nodes {
		st.Nodes[i].Running = nil
	}
	for _, r := range st.Replicas {
		if n := st.node(r.Node); n != nil {
			n.Running = append(n.Running, replicaName(r.App, r.Index, r.Hash))
		}
	}
}

func countHash(st *ClusterState, app, want string) (updated, total int) {
	for _, r := range st.Replicas {
		if r.App == app {
			total++
			if r.Hash == want {
				updated++
			}
		}
	}
	return
}

func TestRollingUpdateAndPause(t *testing.T) {
	now := time.Now()
	st := &ClusterState{Nodes: testNodes(now, "a", "b", "c")}
	upsertApp(st, ClusteredApp{Name: "web", Image: "nginx:1", Replicas: 3})
	scheduleReplicas(st, now)
	markRunning(st)

	upsertApp(st, ClusteredApp{Name: "web", Image: "nginx:2", Replicas: 3})
	if st.app("web").Revision != 2 || len(st.History["web"]) != 1 {
		t.Fatalf("revision/history not recorded: %+v %v", st.app("web"), st.History)
	}
	if upsertApp(st, ClusteredApp{Name: "web", Image: "nginx:2", Replicas: 3}) {
		t.Error("identical spec must not be a change")
	}
	v2 := specHash(*st.app("web"))
	scheduleReplicas(st, now)
	if u, _ := countHash(st, "web", v2); u != 1 {
		t.Fatalf("rollout must replace one replica at a time, got %d", u)
	}
	scheduleReplicas(st, now) // the new replica is not running yet: rollout waits
	if u, _ := countHash(st, "web", v2); u != 1 {
		t.Fatalf("rollout advanced before the new replica ran: %d", u)
	}
	for i := 0; i < 3; i++ {
		markRunning(st)
		scheduleReplicas(st, now)
	}
	if u, n := countHash(st, "web", v2); u != 3 || n != 3 {
		t.Fatalf("rollout did not finish: %d/%d", u, n)
	}

	// A failing revision pauses the rollout after the first replica.
	markRunning(st)
	upsertApp(st, ClusteredApp{Name: "web", Image: "nginx:broken", Replicas: 3})
	v3 := specHash(*st.app("web"))
	scheduleReplicas(st, now)
	for i := range st.Replicas {
		if st.Replicas[i].Hash == v3 {
			st.Replicas[i].Fails, st.Replicas[i].Error = 1, "pull failed"
		}
	}
	markRunning(st)
	for i := range st.Nodes { // the broken replica never runs
		var keep []string
		for _, c := range st.Nodes[i].Running {
			if !strings.HasSuffix(c, v3) {
				keep = append(keep, c)
			}
		}
		st.Nodes[i].Running = keep
	}
	scheduleReplicas(st, now)
	if u, _ := countHash(st, "web", v3); u != 1 {
		t.Fatalf("failing revision must pause the rollout at 1 replica, got %d", u)
	}
	if s := st.appStatus(*st.app("web")); !strings.Contains(s, "updating") || !strings.Contains(s, "pull failed") {
		t.Errorf("status should show the stalled rollout: %s", s)
	}
	for i := range st.Nodes {
		st.Nodes[i].MeshIP = "10.200.0." + string(rune('1'+i))
	}
	if eps := appEndpoints(st)["web"]; len(eps) != 2 {
		t.Errorf("discovery must list only nodes with a running replica, got %v", eps)
	}

	// Rollback: the broken replica is replaced right away, then the rest stays healthy.
	prev := st.History["web"][len(st.History["web"])-1]
	st.History["web"] = st.History["web"][:len(st.History["web"])-1]
	upsertApp(st, prev)
	scheduleReplicas(st, now)
	if u, n := countHash(st, "web", specHash(prev)); u != 3 || n != 3 {
		t.Fatalf("rollback must replace the broken replica immediately: %d/%d", u, n)
	}
	for _, r := range st.Replicas {
		if r.Error != "" || r.Fails != 0 {
			t.Errorf("stale failure after rollback: %+v", r)
		}
	}
}

func TestFailedReplicaMovesToAnotherNode(t *testing.T) {
	now := time.Now()
	st := &ClusterState{Nodes: testNodes(now, "a", "b"), Apps: []ClusteredApp{{Name: "api", Image: "api", Replicas: 1}}}
	scheduleReplicas(st, now)
	first := st.Replicas[0].Node
	st.Replicas[0].Fails = maxReplicaFails
	scheduleReplicas(st, now)
	if r := st.Replicas[0]; r.Node == first || r.Node == "" || r.Avoid != first {
		t.Fatalf("replica should move off %s: %+v", first, r)
	}
}

func TestHostPortConflictsAcrossApps(t *testing.T) {
	now := time.Now()
	st := &ClusterState{Nodes: testNodes(now, "a", "b"), Apps: []ClusteredApp{
		{Name: "one", Image: "x", Replicas: 1, Port: "8080:80"},
		{Name: "two", Image: "y", Replicas: 2, Port: "8080:8080"},
	}}
	scheduleReplicas(st, now)
	perNode, pending := map[string]int{}, 0
	for _, r := range st.Replicas {
		if r.Node == "" {
			pending++
		}
		perNode[r.Node]++
	}
	if perNode["a"] != 1 || perNode["b"] != 1 || pending != 1 {
		t.Fatalf("8080/tcp must be held by one replica per node across apps: %v", st.Replicas)
	}
	if hostPortKey("53:53/udp") != "53/udp" || hostPortKey("8080:80") != "8080/tcp" || hostPortKey("bad") != "" {
		t.Error("hostPortKey")
	}
}

func TestRebalanceAndDrain(t *testing.T) {
	now := time.Now()
	st := &ClusterState{Nodes: testNodes(now, "a"), Apps: []ClusteredApp{{Name: "web", Image: "nginx", Replicas: 4}}}
	scheduleReplicas(st, now)
	markRunning(st)
	st.Nodes = append(st.Nodes, ClusterNode{ID: "b", LastSeen: now})
	scheduleReplicas(st, now)
	if p := placement(st, "web"); p["b"] != 1 {
		t.Fatalf("a new node should receive one replica per pass: %v", p)
	}
	for i := 0; i < 4; i++ {
		markRunning(st)
		scheduleReplicas(st, now)
	}
	if p := placement(st, "web"); p["a"] != 2 || p["b"] != 2 {
		t.Fatalf("not balanced: %v", p)
	}

	// drain = cordon + evict: nothing may land on b again
	st.node("b").Cordoned = true
	for i := range st.Replicas {
		if st.Replicas[i].Node == "b" {
			st.Replicas[i].Node = ""
		}
	}
	scheduleReplicas(st, now)
	if p := placement(st, "web"); p["b"] != 0 || p["a"] != 4 {
		t.Fatalf("drained node must not get replicas: %v", p)
	}
}

func TestSecretsNeverInArgv(t *testing.T) {
	now := time.Now()
	st := &ClusterState{Nodes: testNodes(now, "a"), Apps: []ClusteredApp{{Name: "db", Image: "pg", Replicas: 1,
		Secrets: []string{"dbpass"}, Env: map[string]string{"MODE": "x"}}}}
	scheduleReplicas(st, now)
	as := assignmentsFor(st, "a", map[string]map[string]string{"dbpass": {"PASSWORD": "hunter2"}})
	if len(as) != 1 || as[0].SecretEnv["PASSWORD"] != "hunter2" {
		t.Fatalf("secret not delivered: %+v", as)
	}
	args := strings.Join(runArgs(as[0]), " ")
	if strings.Contains(args, "hunter2") || !strings.Contains(args, "--env-file") || !strings.Contains(args, "MODE=x") {
		t.Fatalf("secret leaked into argv or env-file missing: %s", args)
	}
	if err := validateApp(&ClusteredApp{Name: "db", Image: "pg", Secrets: []string{"nope"}}, nil); err == nil {
		t.Error("unknown secret accepted")
	}
	for _, bad := range []ClusteredApp{
		{Name: "x", Image: "-rm"}, {Name: "x", Image: "a b"}, {Name: "x", Image: "i", Port: "99999:1"},
		{Name: "x", Image: "i", Env: map[string]string{"A B": "1"}}, {Name: "x", Image: "i", Env: map[string]string{"A": "1\nB=2"}},
		{Name: "../x", Image: "i"}, {Name: "x", Image: "i", MeshOnly: true},
	} {
		if validateApp(&bad, nil) == nil {
			t.Errorf("accepted invalid app %+v", bad)
		}
	}
}

func TestMeshAddressingAndHosts(t *testing.T) {
	st := &ClusterState{Nodes: []ClusterNode{{ID: "m", MeshIP: "10.200.0.1"}}}
	ip, err := allocMeshIP(st, "10.200.0.0/16")
	if err != nil || ip != "10.200.0.2" {
		t.Fatalf("allocMeshIP = %q, %v", ip, err)
	}
	if _, err := allocMeshIP(&ClusterState{Nodes: []ClusterNode{{MeshIP: "10.9.0.1"}, {MeshIP: "10.9.0.2"}}}, "10.9.0.0/30"); err == nil {
		t.Error("full /30 should be reported")
	}
	_, pub := generateWgKeypair()
	st = &ClusterState{Nodes: []ClusterNode{
		{ID: "a", IP: "192.0.2.1", MeshIP: "10.200.0.1", WGPubKey: pub},
		{ID: "b", IP: "192.0.2.2", MeshIP: "10.200.0.2", WGPubKey: pub, WGPort: 51999},
		{ID: "c", IP: "192.0.2.3"}, // no key yet: not a peer
	}}
	self, prefix, peers := meshView(st, &st.Nodes[0], "10.200.0.0/16")
	if self != "10.200.0.1" || prefix != 16 || len(peers) != 1 || peers[0].Endpoint != "192.0.2.2:51999" {
		t.Fatalf("meshView = %s %d %+v", self, prefix, peers)
	}

	hosts := "127.0.0.1 localhost\n" + hostsBegin + "\n10.0.0.9\told." + meshDomain + "\n" + hostsEnd + "\n::1 localhost\n"
	got := renderHostsBlock(hosts, map[string][]string{"web": {"10.200.0.1", "10.200.0.2"}})
	if strings.Contains(got, "old.") || !strings.Contains(got, "10.200.0.2\tweb.cluster.ziro") || !strings.Contains(got, "::1 localhost") {
		t.Fatalf("hosts block wrong:\n%s", got)
	}
	if again := renderHostsBlock(got, map[string][]string{"web": {"10.200.0.1", "10.200.0.2"}}); again != got {
		t.Error("hosts rendering must be idempotent")
	}
	if cleared := renderHostsBlock(got, nil); strings.Contains(cleared, hostsBegin) {
		t.Error("empty endpoints should remove the block")
	}
}

func TestJoinTokenExpiryAndLabels(t *testing.T) {
	now := time.Now()
	if joinTokenExpired(&ClusterConfig{}, now) {
		t.Error("no expiry = permanent")
	}
	if !joinTokenExpired(&ClusterConfig{JoinTokenExpires: now.Add(-time.Minute).Format(time.RFC3339)}, now) {
		t.Error("past expiry must be expired")
	}
	if joinTokenExpired(&ClusterConfig{JoinTokenExpires: now.Add(time.Hour).Format(time.RFC3339)}, now) {
		t.Error("future expiry must be valid")
	}
	if got := sanitizeLabel("evil\x1b[2J\nhost", 64); got != "evil[2Jhost" {
		t.Errorf("sanitizeLabel = %q", got)
	}
}
