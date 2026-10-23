package cmd

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// scaleState is a settled cluster: nodes Ready with mesh addresses, apps scheduled.
func scaleState(nodes, apps, replicas int) *ClusterState {
	st := &ClusterState{NodeTokens: map[string]string{}, History: map[string][]ClusteredApp{}, Secrets: map[string]map[string]string{}}
	now := time.Now()
	for i := 0; i < nodes; i++ {
		st.Nodes = append(st.Nodes, ClusterNode{ID: fmt.Sprintf("node-%03d", i), Status: "Ready", LastSeen: now,
			IP: fmt.Sprintf("10.0.%d.%d", i/250, i%250+1), MeshIP: fmt.Sprintf("10.200.%d.%d", i/250, i%250+1),
			WGPubKey: fmt.Sprintf("%043d=", i), WGPort: 51820})
	}
	for a := 0; a < apps; a++ {
		upsertApp(st, ClusteredApp{Name: fmt.Sprintf("app%02d", a), Image: "nginx:1", Replicas: replicas, Port: fmt.Sprint(8000 + a)})
	}
	scheduleReplicas(st, now)
	for i := range st.Replicas { // every replica running where it was placed
		r := st.Replicas[i]
		if n := st.node(r.Node); n != nil {
			n.Running = append(n.Running, replicaName(r.App, r.Index, r.Hash))
		}
	}
	scheduleReplicas(st, now)
	return st
}

// BenchmarkHeartbeatWork is the master's work for one heartbeat on a 100-node, 300-replica
// cluster: the state copy, scheduling and the node's view.
func BenchmarkHeartbeatWork(b *testing.B) {
	st := scaleState(100, 30, 10)
	cidr := "10.200.0.0/16"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := cloneState(st)
		n := &c.Nodes[i%len(c.Nodes)]
		scheduleReplicas(c, time.Now())
		assignmentsFor(c, n.ID, c.Secrets)
		meshView(c, n, cidr)
		appEndpoints(c)
		policyFor(c, n.ID)
		storageFor(c, n.ID)
		hardKey(c)
	}
}

// TestHeartbeatResponseSize reports what one heartbeat answer carries at 100 nodes (go test -v).
func TestHeartbeatResponseSize(t *testing.T) {
	st := scaleState(100, 30, 10)
	n := &st.Nodes[7]
	var resp heartbeatResponse
	resp.Assignments = assignmentsFor(st, n.ID, st.Secrets)
	resp.MeshIP, resp.MeshPrefix, resp.Peers = meshView(st, n, "10.200.0.0/16")
	resp.Endpoints = appEndpoints(st)
	resp.Policy = policyFor(st, n.ID)
	resp.DNSRecords = st.DNSRecords
	b, _ := json.Marshal(resp)
	parts := map[string]any{"assignments": resp.Assignments, "peers": resp.Peers, "endpoints": resp.Endpoints, "policy": resp.Policy}
	for k, v := range parts {
		pb, _ := json.Marshal(v)
		t.Logf("%-12s %6d bytes", k, len(pb))
	}
	t.Logf("total        %6d bytes per heartbeat", len(b))
}

// TestHeartbeatDeltaSize reports an unchanged answer's size at 100 nodes (go test -v).
func TestHeartbeatDeltaSize(t *testing.T) {
	st := scaleState(100, 30, 10)
	n := &st.Nodes[7]
	answer := func() heartbeatResponse {
		var r heartbeatResponse
		r.Assignments = assignmentsFor(st, n.ID, st.Secrets)
		r.MeshIP, r.MeshPrefix, r.Peers = meshView(st, n, "10.200.0.0/16")
		r.Endpoints = appEndpoints(st)
		r.Policy = policyFor(st, n.ID)
		return r
	}
	var d heartbeatDelta
	a := answer()
	a.omitUnchanged(d.have())
	first, _ := json.Marshal(a)
	d.fill(&a)
	b := answer()
	b.omitUnchanged(d.have())
	second, _ := json.Marshal(b)
	t.Logf("first answer %d bytes, unchanged answer %d bytes", len(first), len(second))
}
