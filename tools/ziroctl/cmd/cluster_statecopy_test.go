package cmd

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// richState is a state with something in most kinds of field: nodes, apps, history, replicas,
// Postgres, sandboxes, DNS, secrets, a CA key and sealed bytes.
func richState() *ClusterState {
	st := scaleState(12, 4, 3)
	now := time.Now()
	st.Nodes[0].Labels = map[string]string{"gateway": "true"}
	st.Nodes[1].Conditions = []string{"DiskPressure"}
	upsertApp(st, ClusteredApp{Name: "app00", Image: "nginx:2", Replicas: 3, Port: "80",
		Env: map[string]string{"A": "1"}, Resources: &Resources{Memory: "1Gi"}, ConfigFiles: map[string]string{"x.conf": "y"}})
	st.DNSRecords = []DNSRecord{{Name: "a.example", Type: "A", Value: "10.0.0.1", TTL: 60}}
	st.Sandboxes = map[string]SandboxPlacement{"abcdefghijkl": {Node: "node-001", Owner: "agent", Since: now}}
	st.SnapshotTombstones = map[string]time.Time{"ziro.local/sandbox/a/b:1": now}
	st.PG = map[string]*PGCluster{"db": {Groups: []PGGroup{{Name: "main", Members: []PGMember{
		{ID: "m1", Node: "node-002", Role: pgPrimary, Probe: PGProbe{At: now, OK: true, LSN: 7}, Cmd: &PGCommand{ID: "c1", Op: "promote"}}},
		Notes: map[string]time.Time{"lag": now}}}}}
	st.Secrets = map[string]map[string]string{"db": {"PASS": "s3cret"}}
	st.CAKey = "KEY"
	st.sealed = []byte("sealed-bytes")
	return st
}

// jsonClone is how cloneState copied the state before (the reference).
func jsonClone(st *ClusterState) *ClusterState {
	b, _ := json.Marshal(st)
	c := &ClusterState{}
	json.Unmarshal(b, c)
	initStateMaps(c)
	for name, kv := range st.Secrets {
		m := map[string]string{}
		for k, v := range kv {
			m[k] = v
		}
		c.Secrets[name] = m
	}
	c.CAKey, c.sealed = st.CAKey, append([]byte(nil), st.sealed...)
	return c
}

// The walking copy holds exactly what the JSON round trip held, and shares nothing with its source.
func TestCloneStateMatchesJSON(t *testing.T) {
	st := richState()
	want, _ := json.Marshal(jsonClone(st))
	c := cloneState(st)
	got, _ := json.Marshal(c)
	if !bytes.Equal(got, want) {
		t.Fatalf("copies differ:\n got %s\nwant %s", got, want)
	}
	if c.Secrets["db"]["PASS"] != "s3cret" || c.CAKey != "KEY" || string(c.sealed) != "sealed-bytes" {
		t.Errorf("secrets, CA key or sealed bytes lost: %+v %q %q", c.Secrets, c.CAKey, c.sealed)
	}
	before, _ := json.Marshal(st)
	c.Nodes[0].Labels["gateway"] = "no"
	c.Nodes[1].Conditions[0] = "x"
	c.Apps[0].Env["A"] = "changed"
	c.Apps[0].Resources.Memory = "9Gi"
	c.PG["db"].Groups[0].Members[0].Cmd.Op = "demote"
	c.PG["db"].Groups[0].Notes["lag"] = time.Time{}
	c.Sandboxes["abcdefghijkl"] = SandboxPlacement{}
	c.Secrets["db"]["PASS"] = "leak"
	c.sealed[0] = 'X'
	after, _ := json.Marshal(st)
	if !bytes.Equal(before, after) || st.Secrets["db"]["PASS"] != "s3cret" || st.sealed[0] != 's' {
		t.Error("changing the copy changed the original")
	}
}

// BenchmarkCloneState compares the walking copy with the JSON round trip it replaces.
func BenchmarkCloneState(b *testing.B) {
	st := scaleState(100, 30, 10)
	b.Run("walk", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			cloneState(st)
		}
	})
	b.Run("json", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			jsonClone(st)
		}
	})
}
