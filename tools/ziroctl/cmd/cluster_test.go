package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testNodes(now time.Time, ids ...string) []ClusterNode {
	var ns []ClusterNode
	for _, id := range ids {
		ns = append(ns, ClusterNode{ID: id, LastSeen: now})
	}
	return ns
}

func placement(st *ClusterState, app string) map[string]int {
	m := map[string]int{}
	for _, r := range st.Replicas {
		if r.App == app {
			m[r.Node]++
		}
	}
	return m
}

func TestScheduleSpreadsAndRespectsPortAntiAffinity(t *testing.T) {
	now := time.Now()
	st := &ClusterState{
		Nodes: testNodes(now, "a", "b", "c"),
		Apps: []ClusteredApp{
			{Name: "web", Image: "nginx", Replicas: 4},
			{Name: "api", Image: "api", Replicas: 4, Port: "8080:80"},
		},
	}
	scheduleReplicas(st, now)

	if p := placement(st, "api"); p[""] != 1 || p["a"] != 1 || p["b"] != 1 || p["c"] != 1 {
		t.Errorf("port app must place one per node and leave one pending, got %v", p)
	}
	total := map[string]int{}
	for _, r := range st.Replicas {
		total[r.Node]++
	}
	if total["a"]+total["b"]+total["c"] != 7 || total["a"] > 3 || total["b"] > 3 || total["c"] > 3 {
		t.Errorf("replicas not spread evenly: %v", total)
	}

	// Stable: another pass must not move anything.
	before := append([]Replica(nil), st.Replicas...)
	scheduleReplicas(st, now)
	for i := range before {
		if before[i] != st.Replicas[i] {
			t.Fatalf("scheduler churned replica %v -> %v", before[i], st.Replicas[i])
		}
	}

	// Node c stops heartbeating: its replicas move to a/b, the port replica goes pending.
	st.Nodes[2].LastSeen = now.Add(-2 * nodeTimeout)
	scheduleReplicas(st, now)
	if st.Nodes[2].Status != "NotReady" {
		t.Errorf("stale node should be NotReady")
	}
	for _, r := range st.Replicas {
		if r.Node == "c" {
			t.Errorf("replica %v still on dead node", r)
		}
	}
	if p := placement(st, "web"); p["a"]+p["b"] != 4 {
		t.Errorf("web replicas not rescheduled: %v", p)
	}
	if p := placement(st, "api"); p[""] != 2 {
		t.Errorf("api should have 2 pending with 2 nodes, got %v", p)
	}

	// Scale down and remove.
	st.Apps = []ClusteredApp{{Name: "web", Image: "nginx", Replicas: 1}}
	scheduleReplicas(st, now)
	if len(st.Replicas) != 1 || st.Replicas[0].App != "web" {
		t.Errorf("scale-down/removal wrong: %v", st.Replicas)
	}
}

func TestContainerNameChangesWithSpec(t *testing.T) {
	a := ClusteredApp{Name: "web", Image: "nginx:1", Env: map[string]string{"A": "1"}}
	b := a
	b.Image = "nginx:2"
	if containerName(a, 1) == containerName(b, 1) {
		t.Errorf("image change must produce a new container name")
	}
	if n1, n2 := containerName(a, 1), containerName(a, 1); n1 != n2 || !strings.HasPrefix(n1, "zc-web-1-") {
		t.Errorf("unexpected name %s", containerName(a, 1))
	}
}

func TestPlanReconcile(t *testing.T) {
	desired := []Assignment{{Name: "zc-web-1-aa"}, {Name: "zc-web-2-aa"}, {Name: "zc-api-1-bb"}}
	actual := map[string]bool{"zc-web-1-aa": true, "zc-web-2-aa": false, "zc-web-3-old": true}
	start, restart, remove := planReconcile(desired, actual)
	if len(start) != 1 || start[0].Name != "zc-api-1-bb" {
		t.Errorf("start = %v", start)
	}
	if len(restart) != 1 || restart[0] != "zc-web-2-aa" {
		t.Errorf("restart = %v", restart)
	}
	if len(remove) != 1 || remove[0] != "zc-web-3-old" {
		t.Errorf("remove = %v", remove)
	}
	if args := runArgs(Assignment{Name: "n", App: "x", Image: "--privileged"}); args[len(args)-2] != "--" {
		t.Errorf("image must follow '--' so it can never be parsed as a flag: %v", args)
	}
}

func TestClusterJoinHeartbeatLeave(t *testing.T) {
	clusterDir = t.TempDir()
	defer func() { clusterDir = "/etc/ziro/cluster" }()

	srv := httptest.NewTLSServer(newClusterServer().handler())
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")
	sum := sha256.Sum256(srv.Certificate().Raw)
	caHash := "sha256:" + hex.EncodeToString(sum[:])

	master := &ClusterConfig{ClusterID: "ziro-test", Role: "master", NodeID: "master-1", MasterAddr: addr,
		JoinToken: "jointoken", NodeToken: "mastertoken", CAHash: caHash}
	if err := saveClusterConfig(master); err != nil {
		t.Fatal(err)
	}
	_ = withState(func(st *ClusterState) error {
		st.NodeTokens["master-1"] = hashToken("mastertoken")
		st.Nodes = []ClusterNode{{ID: "master-1", Role: "master", LastSeen: time.Now()}}
		st.Apps = []ClusteredApp{{Name: "web", Image: "nginx", Replicas: 2, Port: "80:80"}}
		return nil
	})

	if err := clusterPost(addr, "sha256:"+strings.Repeat("0", 64), "/cluster/v1/join", "Bearer jointoken", joinRequest{}, nil); err == nil {
		t.Fatal("join must fail when the certificate pin does not match")
	}
	if err := clusterPost(addr, caHash, "/cluster/v1/join", "Bearer wrong", joinRequest{}, nil); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("wrong join token must be 401, got %v", err)
	}

	var jr joinResponse
	if err := clusterPost(addr, caHash, "/cluster/v1/join", "Bearer jointoken", joinRequest{Hostname: "w1"}, &jr); err != nil {
		t.Fatal(err)
	}
	worker := &ClusterConfig{NodeID: jr.NodeID, NodeToken: jr.NodeToken}

	var hb heartbeatResponse
	if err := clusterPost(addr, caHash, "/cluster/v1/heartbeat", nodeAuth(worker), heartbeatRequest{}, &hb); err != nil {
		t.Fatal(err)
	}
	if len(hb.Assignments) != 1 || hb.Assignments[0].Image != "nginx" {
		t.Fatalf("worker should get one of the two port-bound replicas, got %+v", hb.Assignments)
	}

	bad := &ClusterConfig{NodeID: jr.NodeID, NodeToken: "forged"}
	if err := clusterPost(addr, caHash, "/cluster/v1/heartbeat", nodeAuth(bad), heartbeatRequest{}, nil); err == nil {
		t.Fatal("forged node token must be rejected")
	}

	if err := clusterPost(addr, caHash, "/cluster/v1/leave", nodeAuth(worker), struct{}{}, nil); err != nil {
		t.Fatal(err)
	}
	st, _ := readState()
	if len(st.Nodes) != 1 || st.NodeTokens[jr.NodeID] != "" {
		t.Fatalf("node not removed on leave: %+v", st.Nodes)
	}
	if err := clusterPost(addr, caHash, "/cluster/v1/heartbeat", nodeAuth(worker), heartbeatRequest{}, nil); err == nil {
		t.Fatal("departed node must no longer authenticate")
	}
}
