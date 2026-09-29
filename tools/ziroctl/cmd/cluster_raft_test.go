package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

type testMaster struct {
	rs    *raftStore
	trans *raft.InmemTransport
	dir   string
}

// newTestGroup starts n in-process Raft masters (in-memory transport and stores); master 0
// bootstraps from imported.
func newTestGroup(t *testing.T, n int, imported *ClusterState) []*testMaster {
	t.Helper()
	var ms []*testMaster
	for i := 0; i < n; i++ {
		_, trans := raft.NewInmemTransport(raft.ServerAddress(fmt.Sprintf("m%d", i)))
		ms = append(ms, &testMaster{trans: trans, dir: t.TempDir()})
	}
	for _, a := range ms {
		for _, b := range ms {
			if a != b {
				a.trans.Connect(b.trans.LocalAddr(), b.trans)
			}
		}
	}
	for i, m := range ms {
		store := raft.NewInmemStore()
		var imp func() (*ClusterState, error)
		if i == 0 {
			imp = func() (*ClusterState, error) { return cloneState(imported), nil }
		}
		rs, err := newRaftStore(fmt.Sprintf("m%d", i), m.dir, m.trans, store, store, raft.NewInmemSnapshotStore(), i == 0, imp)
		if err != nil {
			t.Fatal(err)
		}
		m.rs = rs
		t.Cleanup(func() { _ = rs.r.Shutdown().Error() })
	}
	waitFor(t, "first leader", func() bool { return ms[0].rs.isLeader() })
	for _, m := range ms[1:] {
		if err := ms[0].rs.r.AddVoter(raft.ServerID(m.rs.id), m.trans.LocalAddr(), 0, 5*time.Second).Error(); err != nil {
			t.Fatal(err)
		}
	}
	return ms
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func leaderOf(ms []*testMaster) *testMaster {
	for _, m := range ms {
		if m.rs.isLeader() {
			return m
		}
	}
	return nil
}

func TestRaftControlPlane(t *testing.T) {
	imported := &ClusterState{NodeTokens: map[string]string{}, History: map[string][]ClusteredApp{},
		Secrets: map[string]map[string]string{"db": {"PASS": "s3cret"}}, CAKey: "KEY", JoinToken: "tok",
		Nodes: []ClusterNode{{ID: "n1", Status: "Ready", LastSeen: time.Now()}, {ID: "dead", Status: "NotReady", LastSeen: time.Now().Add(-time.Hour)}}}
	upsertApp(imported, ClusteredApp{Name: "web", Image: "nginx", Replicas: 1})
	ms := newTestGroup(t, 3, imported)
	lead := ms[0].rs

	// The import is the first entry and reaches every master's files (secrets and CA key too).
	for _, m := range ms {
		waitFor(t, "replication", func() bool { b, _ := m.rs.fsm.latest(); return len(b) > 0 })
		st, err := loadStateAt(m.dir)
		if err != nil || st.app("web") == nil || st.Secrets["db"]["PASS"] != "s3cret" || st.CAKey != "KEY" {
			t.Fatalf("%s files: %+v %v", m.rs.id, st, err)
		}
	}

	// Liveness-only changes are not committed; desired-state changes are.
	_, idx := lead.fsm.latest()
	if err := lead.mutate(func(st *ClusterState) error { st.node("n1").LastSeen = time.Now(); st.node("n1").Running = []string{"x"}; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, now := lead.fsm.latest(); now != idx {
		t.Fatal("a liveness-only change was committed")
	}
	if err := lead.mutate(func(st *ClusterState) error { st.app("web").Replicas = 3; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, now := lead.fsm.latest(); now == idx {
		t.Fatal("a desired-state change was not committed")
	}

	// CAS proposals: a stale version conflicts; a current one lands and keeps liveness.
	st, ver, _ := lead.snapshot()
	st.app("web").Image = "nginx:2"
	st.node("n1").Running = nil // the CLI's copy of liveness is ignored
	if err := lead.propose(ver-1, cloneState(st)); !errors.Is(err, errConflict) {
		t.Fatalf("stale proposal: %v", err)
	}
	if err := lead.propose(ver, st); err != nil {
		t.Fatal(err)
	}
	cur, _, _ := lead.snapshot()
	if cur.app("web").Image != "nginx:2" || len(cur.node("n1").Running) != 1 || cur.CAKey != "KEY" {
		t.Fatalf("after propose: %+v", cur.node("n1"))
	}

	// Followers refuse writes.
	if err := ms[1].rs.mutate(func(*ClusterState) error { return nil }); !errors.Is(err, errNotLeader) {
		t.Fatalf("follower write: %v", err)
	}

	// Leader failure: a follower takes over with the committed state and grants a grace period
	// to nodes that were Ready (not to long-dead ones).
	ms[0].trans.DisconnectAll()
	for _, m := range ms[1:] {
		m.trans.Disconnect(ms[0].trans.LocalAddr())
	}
	_ = lead.r.Shutdown().Error()
	waitFor(t, "new leader", func() bool { return leaderOf(ms[1:]) != nil })
	nl := leaderOf(ms[1:]).rs
	got, _, err := nl.snapshot()
	if err != nil || got.app("web").Image != "nginx:2" || got.app("web").Replicas != 3 {
		t.Fatalf("new leader state: %v", err)
	}
	if time.Since(got.node("n1").LastSeen) > 5*time.Second || time.Since(got.node("dead").LastSeen) < 30*time.Minute {
		t.Fatalf("grace: n1 %v, dead %v", got.node("n1").LastSeen, got.node("dead").LastSeen)
	}
	if err := nl.mutate(func(st *ClusterState) error { st.app("web").Replicas = 2; return nil }); err != nil {
		t.Fatalf("write after failover: %v", err)
	}
	if err := nl.removeMember("m0"); err != nil {
		t.Fatalf("remove dead master: %v", err)
	}
	other := ms[1].rs
	if other == nl {
		other = ms[2].rs
	}
	if err := nl.removeMember(other.id); err != nil {
		t.Fatalf("remove second master: %v", err)
	}
	if err := nl.removeMember(nl.id); err == nil {
		t.Fatal("the last voter must not be removable")
	}
}

func loadStateAt(dir string) (*ClusterState, error) {
	old := clusterDir
	clusterDir = dir
	defer func() { clusterDir = old }()
	st, err := loadStateFile()
	if err == nil && st.CAKey == "" {
		if b, err := os.ReadFile(filepath.Join(dir, "ca.key")); err == nil {
			st.CAKey = string(b)
		}
	}
	return st, err
}
