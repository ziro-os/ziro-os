package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// policyCluster: api (8080) on a, web on b, other on c.
func policyCluster(def string) *ClusterState {
	now := time.Now()
	st := &ClusterState{Nodes: testNodes(now, "a", "b", "c"), PolicyDefault: def}
	for i, ip := range []string{"10.200.0.1", "10.200.0.2", "10.200.0.3"} {
		st.Nodes[i].MeshIP = ip
	}
	st.Apps = []ClusteredApp{
		{Name: "api", Image: "api:1", Replicas: 1, Port: "8080:80", AllowFrom: []string{"web"}},
		{Name: "web", Image: "web:1", Replicas: 1, Port: "80:80"},
		{Name: "other", Image: "o:1", Replicas: 1},
	}
	st.Replicas = []Replica{{App: "api", Index: 0, Node: "a"}, {App: "web", Index: 0, Node: "b"}, {App: "other", Index: 0, Node: "c"}}
	return st
}

func TestPolicyFor(t *testing.T) {
	st := policyCluster("deny")
	p := policyFor(st, "a")
	if !p.Deny || len(p.Rules) != 1 || p.Rules[0].Port != 8080 || p.Rules[0].Proto != "tcp" ||
		strings.Join(p.Rules[0].Sources, ",") != "10.200.0.2" {
		t.Fatalf("api rule: %+v", p)
	}
	// web has no allow_from: its port gets no rule, so the trailing drop blocks it.
	if p := policyFor(st, "b"); !p.Deny || len(p.Rules) != 0 {
		t.Fatalf("web must be closed: %+v", p)
	}
	st.app("api").AllowFrom = []string{"*"}
	if got := strings.Join(policyFor(st, "a").Rules[0].Sources, ","); got != "10.200.0.1,10.200.0.2,10.200.0.3" {
		t.Fatalf("'*' sources = %s", got)
	}
	st.app("api").AllowFrom = []string{"ghost"} // app with no replicas admits nobody
	if p := policyFor(st, "a"); len(p.Rules) != 0 {
		t.Fatalf("unplaced source app must admit nothing: %+v", p)
	}
	if p := policyFor(policyCluster(""), "a"); p.Deny || len(p.Rules) != 0 {
		t.Fatalf("legacy clusters (no default) stay open: %+v", p)
	}
}

func TestBuildPolicyScript(t *testing.T) {
	s, err := buildPolicyScript(policyFor(policyCluster("deny"), "a"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"delete table inet ziro_cluster\n",
		"type filter hook forward priority -10; policy accept;",
		`iifname "ziro0" ip saddr { 10.200.0.2 } meta l4proto tcp ct original proto-dst 8080 accept`,
		`iifname "ziro0" drop`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("script missing %q:\n%s", want, s)
		}
	}
	if s2, _ := buildPolicyScript(policyFor(policyCluster("deny"), "a")); s2 != s {
		t.Fatal("rendering must be deterministic (the agent skips unchanged policies)")
	}
	if s, _ := buildPolicyScript(&MeshPolicy{Deny: false}); strings.Contains(s, "drop") {
		t.Fatalf("allow mode must only remove the table:\n%s", s)
	}
	for _, bad := range []MeshRule{
		{Port: 80, Proto: "tcp", Sources: []string{"10.0.0.1 } accept; drop {"}},
		{Port: 0, Proto: "tcp", Sources: []string{"10.0.0.1"}},
		{Port: 80, Proto: "icmp", Sources: []string{"10.0.0.1"}},
	} {
		if _, err := buildPolicyScript(&MeshPolicy{Deny: true, Rules: []MeshRule{bad}}); err == nil {
			t.Fatalf("accepted invalid rule %+v", bad)
		}
	}
}

func TestAuditChain(t *testing.T) {
	old := auditPath
	auditPath = filepath.Join(t.TempDir(), "audit.log")
	defer func() { auditPath = old }()

	for _, a := range []string{"one", "two", "three"} {
		if err := auditLog("uid:0(root)", "", a, "t", nil); err != nil {
			t.Fatal(err)
		}
	}
	if n, _, err := verifyAudit(auditFiles()); err != nil || n != 3 {
		t.Fatalf("verify: %d %v", n, err)
	}
	// Rotation continues the chain in the next file.
	if err := os.Rename(auditPath, auditPath+".1"); err != nil {
		t.Fatal(err)
	}
	_ = auditLog("uid:0(root)", "", "four", "t", nil)
	if n, _, err := verifyAudit(auditFiles()); err != nil || n != 4 {
		t.Fatalf("verify across rotation: %d %v", n, err)
	}
	// Tamper with a record: the next record's link breaks.
	b, _ := os.ReadFile(auditPath + ".1")
	_ = os.WriteFile(auditPath+".1", []byte(strings.Replace(string(b), `"action":"two"`, `"action":"TWO"`, 1)), 0600)
	if _, _, err := verifyAudit(auditFiles()); err == nil || !strings.Contains(err.Error(), ":3:") {
		t.Fatalf("tampering not detected at line 3: %v", err)
	}
}

func TestRedactArgs(t *testing.T) {
	got := strings.Join(redactArgs([]string{
		"cluster", "secret", "set", "db", "PASSWORD=hunter2", "--token", "abc", "--token=abc", "-e", "K=v", "--env=K=v", "--name", "web",
	}), " ")
	want := "cluster secret set db PASSWORD=<redacted> --token <redacted> --token=<redacted> -e K=<redacted> --env=K=<redacted> --name web"
	if got != want || strings.Contains(got, "hunter2") {
		t.Fatalf("redactArgs:\n got %s\nwant %s", got, want)
	}
}
