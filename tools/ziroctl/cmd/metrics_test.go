package cmd

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestRenderMetrics(t *testing.T) {
	now := time.Now()
	st := &ClusterState{PolicyDefault: "deny", DEKID: "k1",
		Nodes: []ClusterNode{{ID: "m1", Role: "master", Status: "Ready", TokenIssued: now.Add(-time.Hour)},
			{ID: "w\"1", Role: "worker", Status: "NotReady"}},
		Apps:     []ClusteredApp{{Name: "web", Replicas: 2}},
		Replicas: []Replica{{App: "web", Index: 1, Node: "m1"}, {App: "web", Index: 2, Node: "w\"1"}}}
	st.Nodes[0].Running = []string{replicaName("web", 1, "")}
	out := renderMetrics(hostMetrics{MemTotal: 1 << 30, Services: map[string]bool{"sshd": true, "gateway": false}}, st,
		[]memberView{{ID: "m1", Suffrage: "Voter", Leader: true}}, "m1", now)

	for _, want := range []string{
		"ziro_up 1\n",
		`ziro_service_up{service="gateway"} 0`,
		`ziro_cluster_node_ready{node="w\"1",role="worker"} 0`,
		`ziro_cluster_app_replicas{app="web",state="desired"} 2`,
		`ziro_cluster_app_replicas{app="web",state="running"} 1`,
		`ziro_cluster_raft_leader 1`,
		`ziro_cluster_security{control="secrets_sealed"} 1`,
		`ziro_cluster_security{control="mesh_policy_deny"} 1`,
		`ziro_cluster_node_token_age_seconds{node="m1"} 3600`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	// Text-format validity: every sample line is well formed, and each family's samples are
	// contiguous right after its TYPE line.
	sample := regexp.MustCompile(`^([a-z_]+)(\{[a-z_]+="(\\.|[^"\\])*"(,[a-z_]+="(\\.|[^"\\])*")*\})? -?[0-9.e+]+$`)
	seen, current := map[string]bool{}, ""
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.HasPrefix(l, "# TYPE ") {
			current = strings.Fields(l)[2]
			if seen[current] {
				t.Fatalf("family %s declared twice", current)
			}
			seen[current] = true
			continue
		}
		if strings.HasPrefix(l, "#") {
			continue
		}
		m := sample.FindStringSubmatch(l)
		if m == nil {
			t.Fatalf("malformed sample line %q", l)
		}
		if m[1] != current {
			t.Fatalf("sample %q outside its family block (%s)", l, current)
		}
	}
	if host := renderMetrics(hostMetrics{}, nil, nil, "", now); strings.Contains(host, "ziro_cluster_") {
		t.Fatal("non-masters must not report cluster metrics")
	}
}
