package cmd

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// pgWorld simulates the nodes and the Postgres inside the member containers, so the controller can
// be driven through failures without a database: it applies the controller's decisions to the state
// (pgPass, scheduleReplicas), runs the orders the way an agent would, and feeds probes back in.
type pgWorld struct {
	t     *testing.T
	st    *ClusterState
	now   time.Time
	down  map[string]bool // nodes that are off
	pg    map[string]*simPG
	done  map[string]bool // orders already executed
	log   []string        // orders run, "app op arg"
	fails map[string]bool // ops that fail ("promote")
	// replicate: replicas follow the primary's WAL (false simulates a lagging replica set).
	stalled map[string]bool // member apps whose replication is stuck
}

type simPG struct {
	up       bool
	primary  bool
	lsn      uint64
	tli      int
	readonly bool
	sync     string
	slots    map[string]bool
	restart  bool // came back from a demote: restarts as a replica
}

func newPGWorld(t *testing.T, nodes int) *pgWorld {
	t.Helper()
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	st := &ClusterState{PodCIDR: "10.200.0.0/16", Secrets: map[string]map[string]string{}, History: map[string][]ClusteredApp{}}
	for i := 1; i <= nodes; i++ {
		st.Nodes = append(st.Nodes, ClusterNode{ID: fmt.Sprintf("n%d", i), Status: "Ready", LastSeen: now, PodCIDR: fmt.Sprintf("10.200.%d.0/24", i), MeshIP: fmt.Sprintf("10.100.0.%d", i)})
	}
	w := &pgWorld{t: t, st: st, now: now, down: map[string]bool{}, pg: map[string]*simPG{}, done: map[string]bool{},
		fails: map[string]bool{}, stalled: map[string]bool{}}
	old := pgNow
	pgNow = func() time.Time { return w.now }
	t.Cleanup(func() { pgNow = old })
	return w
}

func (w *pgWorld) create(o pgCreateOpts) *PGCluster {
	w.t.Helper()
	if o.Name == "" {
		o.Name = "db"
	}
	c, err := pgCreate(w.st, o, w.now)
	if err != nil {
		w.t.Fatal(err)
	}
	return c
}

func (w *pgWorld) cluster() *PGCluster { return w.st.PG["db"] }

func (w *pgWorld) member(group, id string) *PGMember {
	return w.cluster().group(group).member(id)
}

func (w *pgWorld) app(group, id string) string { return w.cluster().memberApp(group, id) }

// step advances time by d and runs one controller pass and one round of heartbeats.
func (w *pgWorld) step(d time.Duration) {
	w.t.Helper()
	w.now = w.now.Add(d)
	for i := range w.st.Nodes {
		if !w.down[w.st.Nodes[i].ID] {
			w.st.Nodes[i].LastSeen = w.now
		}
	}
	pgPass(w.st, w.now)
	scheduleReplicas(w.st, w.now)
	for i := range w.st.Nodes {
		n := &w.st.Nodes[i]
		n.Running = nil
		if w.down[n.ID] {
			continue
		}
		for _, r := range w.st.Replicas {
			if r.Node == n.ID {
				n.Running = append(n.Running, replicaName(r.App, r.Index, r.Hash))
			}
		}
	}
	w.runPostgres()
	for _, n := range w.st.Nodes {
		if w.down[n.ID] {
			continue
		}
		var reports []PGReport
		for _, c := range w.st.PG {
			for _, g := range c.Groups {
				for _, m := range g.Members {
					app := c.memberApp(g.Name, m.ID)
					if s := w.pg[app]; s != nil && s.up && m.Node == n.ID {
						primaryUp := false
						for _, o := range w.pg {
							primaryUp = primaryUp || o.up && o.primary
						}
						reports = append(reports, PGReport{App: app, OK: true, Recovery: !s.primary, LSN: formatLSN(s.lsn), Timeline: s.tli,
							Streaming: !s.primary && primaryUp && !w.stalled[app]})
					}
				}
			}
		}
		var results []PGResult
		for _, o := range pgOrdersFor(w.st, n.ID) {
			if w.done[o.ID] {
				continue
			}
			w.done[o.ID] = true
			res := w.exec(o)
			results = append(results, res)
		}
		pgIngest(w.st, n.ID, reports, results, w.now)
	}
}

// runPostgres starts the members the cluster says should run and replicates WAL.
func (w *pgWorld) runPostgres() {
	for _, c := range w.st.PG {
		for _, g := range c.Groups {
			for _, m := range g.Members {
				app := c.memberApp(g.Name, m.ID)
				s := w.pg[app]
				if s == nil {
					s = &simPG{slots: map[string]bool{}, tli: 1}
					w.pg[app] = s
					if m.Init == pgPrimary && m.Role == pgPrimary {
						s.primary, s.up = true, true
					}
				}
				nodeUp := !w.down[m.Node]
				if !nodeUp {
					s.up = false
					continue
				}
				if !s.up && (s.restart || m.Init == pgReplica || s.primary) {
					s.up = true // the container (re)started
					if s.restart {
						s.primary, s.restart = false, false
					}
				}
			}
		}
	}
	// A replica follows the primary that is up.
	var primary *simPG
	for _, s := range w.pg {
		if s.up && s.primary {
			primary = s
		}
	}
	for app, s := range w.pg {
		if s.up && !s.primary && primary != nil && !w.stalled[app] {
			s.lsn, s.tli = primary.lsn, primary.tli
		}
	}
}

// write adds WAL on the primary that is up and not read-only.
func (w *pgWorld) write(n uint64) bool {
	for _, s := range w.pg {
		if s.up && s.primary {
			if s.readonly {
				return false
			}
			s.lsn += n
			return true
		}
	}
	return false
}

func (w *pgWorld) exec(o PGOrder) PGResult {
	w.log = append(w.log, o.App+" "+o.Op+" "+o.Arg)
	if err := validPGCommand(o.Op, o.Arg); err != nil {
		return PGResult{ID: o.ID, Msg: err.Error()}
	}
	if w.fails[o.Op] {
		return PGResult{ID: o.ID, Msg: "simulated failure"}
	}
	s := w.pg[o.App]
	switch o.Op {
	case opPromote:
		s.primary, s.tli, s.readonly = true, s.tli+1, false
	case opDemote:
		s.up, s.restart, s.readonly = false, true, false
	case opReadonly:
		s.readonly = true
	case opWritable:
		s.readonly = false
	case opSetSync:
		s.sync = o.Arg
	case opSlots:
		for _, n := range strings.Split(o.Arg, ",") {
			s.slots[n] = true
		}
	case opDropSlot:
		delete(s.slots, o.Arg)
	}
	return PGResult{ID: o.ID, OK: true}
}

// settle runs steps until nothing changes for a while (members up, joined, sync applied).
func (w *pgWorld) settle(n int) {
	w.t.Helper()
	for i := 0; i < n; i++ {
		w.step(5 * time.Second)
	}
}

func (w *pgWorld) primaryOf(group string) string {
	if p := w.cluster().group(group).primary(); p != nil {
		return p.ID
	}
	return ""
}

func (w *pgWorld) events(group string) string {
	var b strings.Builder
	for _, e := range w.cluster().group(group).Events {
		b.WriteString(e.Msg + "; ")
	}
	return b.String()
}

// ---- tests ----

func TestPGCreateSpreadsMembersAcrossNodes(t *testing.T) {
	w := newPGWorld(t, 3)
	c := w.create(pgCreateOpts{Replicas: 2})
	nodes := map[string]bool{}
	for _, m := range c.Groups[0].Members {
		nodes[m.Node] = true
	}
	if len(c.Groups[0].Members) != 3 || len(nodes) != 3 || c.Groups[0].Members[0].Role != pgPrimary {
		t.Fatalf("members: %+v", c.Groups[0].Members)
	}
	if got := w.st.Secrets["pg-db"]; len(got["POSTGRES_PASSWORD"]) != 32 || len(got["PG_REPL_PASSWORD"]) != 32 || got["PG_SUPERUSER_PASSWORD"] == got["PG_REPL_PASSWORD"] {
		t.Fatalf("secrets: %v", got)
	}

	w2 := newPGWorld(t, 2)
	if _, err := pgCreate(w2.st, pgCreateOpts{Name: "db", Replicas: 2}, w2.now); err == nil || !strings.Contains(err.Error(), "--colocate") {
		t.Fatalf("three members on two nodes: %v", err)
	}
	if _, err := pgCreate(w2.st, pgCreateOpts{Name: "db", Replicas: 2, Colocate: true}, w2.now); err != nil {
		t.Fatalf("colocate: %v", err)
	}
	w3 := newPGWorld(t, 3)
	w3.st.PodCIDR = ""
	if _, err := pgCreate(w3.st, pgCreateOpts{Name: "db"}, w3.now); err == nil || !strings.Contains(err.Error(), "pod network") {
		t.Fatalf("no pod network: %v", err)
	}
	for _, bad := range []pgCreateOpts{{Name: "Bad-Name"}, {Name: "db", Version: "9"}, {Name: "db", Replicas: 99}, {Name: "db", Shards: 2}} {
		if _, err := pgCreate(newPGWorld(t, 3).st, bad, w.now); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestPGMembersAreRenderedAsPinnedApps(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2, Resources: &Resources{Memory: "4Gi", CPUs: 4}})
	w.settle(3)
	if len(w.st.Apps) != 3 {
		t.Fatalf("apps: %d", len(w.st.Apps))
	}
	for _, g := range w.cluster().Groups {
		for _, m := range g.Members {
			a := w.st.app(w.app(g.Name, m.ID))
			if a == nil || a.Node != m.Node || a.Replicas != 1 || !a.stickyData() || !a.Replicated || a.StopTimeout != pgStopTimeout ||
				a.Network != "pod" || a.Env["ZIRO_PG_MEMBER"] != m.ID || a.Env["ZIRO_PG_RW"] != "db-main-rw.cluster.ziro" ||
				!slices.Equal(a.Args, []string{"bash", "/etc/ziro-config/entry.sh"}) || !slices.Equal(a.Secrets, []string{"pg-db"}) ||
				a.ConfigFiles["entry.sh"] == "" || !strings.Contains(a.ConfigFiles["postgresql.conf"], "shared_buffers = 1024MB") {
				t.Fatalf("member app: %+v", a)
			}
		}
	}
	// The replicas land on the nodes the members are pinned to.
	for _, r := range w.st.Replicas {
		_, g, m := pgFind(w.st, r.App)
		if m == nil || r.Node != m.Node {
			t.Fatalf("replica %+v of %v is not on its pinned node", r, g)
		}
	}
	// Re-rendering changes nothing: no member restarts for a controller pass.
	before := w.st.app(w.app("main", "m2")).Revision
	w.settle(5)
	if after := w.st.app(w.app("main", "m2")).Revision; after != before {
		t.Fatalf("revision moved from %d to %d without a change", before, after)
	}
	// The role file follows the role without touching the spec.
	if got := pgDynamic(w.st, w.app("main", "m1")); got["role"] != "role=primary\nepoch=0\n" {
		t.Fatalf("primary role file: %q", got)
	}
	if got := pgDynamic(w.st, w.app("main", "m2")); got["role"] != "role=replica\nepoch=0\n" {
		t.Fatalf("replica role file: %q", got)
	}
	if pgDynamic(w.st, "web") != nil {
		t.Fatal("other apps have no role file")
	}
}

func TestPGReplicasJoinAndSyncFollows(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(6)
	g := w.cluster().group("main")
	for _, id := range []string{"m2", "m3"} {
		if m := g.member(id); !m.Joined || !m.ready(w.now) {
			t.Fatalf("%s did not join: %+v", id, m)
		}
	}
	if g.Sync != "ANY 1 (m2, m3)" || w.pg[w.app("main", "m1")].sync != "ANY 1 (m2, m3)" {
		t.Fatalf("synchronous standbys: %q / %q (%s)", g.Sync, w.pg[w.app("main", "m1")].sync, w.events("main"))
	}
	// One replica is not enough for a quorum: asynchronous.
	w1 := newPGWorld(t, 2)
	w1.create(pgCreateOpts{Replicas: 1})
	w1.settle(6)
	if g := w1.cluster().group("main"); g.Sync != "" || w1.pg[w1.app("main", "m1")].sync != "" {
		t.Fatalf("one replica must stay asynchronous: %q", g.Sync)
	}
	// Sync off is off.
	w2 := newPGWorld(t, 3)
	w2.create(pgCreateOpts{Replicas: 2, Sync: pgSyncOff})
	w2.settle(6)
	if w2.cluster().group("main").Sync != "" {
		t.Fatal("sync off")
	}
	for n, want := range map[int]int{0: 0, 1: 0, 2: 1, 3: 2, 7: 2} {
		if got := pgQuorum(n); got != want {
			t.Errorf("quorum(%d) = %d, want %d", n, got, want)
		}
	}
}

func TestPGFailoverPromotesTheMostAdvancedReplica(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(6)
	w.write(1000)
	w.settle(2)
	// m3 receives a little more than m2 before the primary dies (m2 stalls).
	w.stalled[w.app("main", "m2")] = true
	w.write(500)
	w.settle(2)
	oldNode := w.member("main", "m1").Node
	w.down[oldNode] = true
	w.settle(3) // inside the grace period: nothing happens
	if w.primaryOf("main") != "m1" {
		t.Fatalf("the controller reacted before the grace period: %s", w.events("main"))
	}
	w.step(pgGrace + 5*time.Second)
	w.settle(3)
	g := w.cluster().group("main")
	if w.primaryOf("main") != "m3" || g.Epoch != 1 || g.member("m1").Role != pgFenced {
		t.Fatalf("after failover primary=%s epoch=%d old=%s (%s)", w.primaryOf("main"), g.Epoch, g.member("m1").Role, w.events("main"))
	}
	if !slices.Contains(w.log, w.app("main", "m3")+" promote ") {
		t.Fatalf("orders: %v", w.log)
	}
	// The new primary's slots and synchronous standbys are re-established.
	w.settle(4)
	if g.Slots != g.Epoch || !w.pg[w.app("main", "m3")].slots[pgSlot("m2")] {
		t.Fatalf("slots after promotion: %d %v", g.Slots, w.pg[w.app("main", "m3")].slots)
	}
	// The read-write name moves; the read-only name serves the other replica.
	eps := podEndpoints(w.st)
	rwIP := memberIP(w.st, w.app("main", "m3"))
	if rwIP == "" || !slices.Equal(eps["db-main-rw"], []string{rwIP}) || !slices.Equal(eps["db-rw"], []string{rwIP}) {
		t.Fatalf("rw endpoints: %v (want %s)", eps["db-rw"], rwIP)
	}

	// The old primary's node comes back: its container restarts as a replica and the member rejoins.
	w.down[oldNode] = false
	w.pg[w.app("main", "m1")].restart = true
	w.settle(6)
	if m := g.member("m1"); m.Role != pgReplica {
		t.Fatalf("m1 after returning: %s (%s)", m.Role, w.events("main"))
	}
}

func TestPGFailoverRefusesWhenAcknowledgedWritesMightBeLost(t *testing.T) {
	// Two replicas, one acknowledgement needed: both must be reachable to be sure.
	w := newPGWorld(t, 5)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(6)
	w.down[w.member("main", "m1").Node] = true
	w.down[w.member("main", "m2").Node] = true
	w.step(pgGrace + 5*time.Second)
	w.settle(3)
	if w.primaryOf("main") != "m1" {
		t.Fatalf("promoted with a replica unreachable: %s", w.events("main"))
	}
	if !strings.Contains(w.events("main"), "only 1 of 2 replicas answer") {
		t.Fatalf("the refusal must be visible: %s", w.events("main"))
	}
	// With three replicas (two acknowledgements) one missing replica is fine.
	w3 := newPGWorld(t, 6)
	w3.create(pgCreateOpts{Replicas: 3})
	w3.settle(8)
	w3.down[w3.member("main", "m1").Node] = true
	w3.down[w3.member("main", "m2").Node] = true
	w3.step(pgGrace + 5*time.Second)
	w3.settle(3)
	if got := w3.primaryOf("main"); got != "m3" && got != "m4" {
		t.Fatalf("three replicas, two acknowledgements, one missing: %q (%s)", got, w3.events("main"))
	}
	// An asynchronous cluster promotes its only replica.
	wa := newPGWorld(t, 2)
	wa.create(pgCreateOpts{Replicas: 1})
	wa.settle(6)
	wa.down[wa.member("main", "m1").Node] = true
	wa.step(pgGrace + 5*time.Second)
	wa.settle(3)
	if wa.primaryOf("main") != "m2" {
		t.Fatalf("async failover: %s", wa.events("main"))
	}
	for r, want := range map[[3]int]bool{{2, 2, 1}: true, {1, 2, 1}: false, {2, 3, 2}: true, {1, 3, 2}: false, {1, 1, 0}: true, {0, 1, 0}: false} {
		if got := pgSafeToPromote(r[0], r[1], r[2]); got != want {
			t.Errorf("safe(%v) = %v", r, got)
		}
	}
}

func TestPGNoFailoverDuringAPartition(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(6)
	// Two of three nodes silent for longer than the node timeout: the master's own network is the
	// likelier fault, so no primary is declared dead.
	w.down["n1"], w.down["n2"] = true, true
	w.step(nodeTimeout + 5*time.Second)
	w.settle(4)
	if w.primaryOf("main") != "m1" || w.cluster().group("main").Epoch != 0 {
		t.Fatalf("failed over during a partition: %s", w.events("main"))
	}
}

func TestPGSwitchoverLosesNothing(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(6)
	w.write(4096)
	w.settle(2)
	last := w.pg[w.app("main", "m1")].lsn
	if err := pgRequestSwitchover(w.st, "db", "", "m2", w.now); err != nil {
		t.Fatal(err)
	}
	if err := pgRequestSwitchover(w.st, "db", "", "m3", w.now); err == nil {
		t.Fatal("a second switchover while one is running")
	}
	w.settle(1)
	if w.write(1) {
		t.Fatal("the old primary must refuse writes while a switchover is in progress")
	}
	w.settle(8)
	g := w.cluster().group("main")
	if w.primaryOf("main") != "m2" || g.Switch != nil || g.Epoch != 1 {
		t.Fatalf("after switchover: primary=%s switch=%v epoch=%d (%s)", w.primaryOf("main"), g.Switch, g.Epoch, w.events("main"))
	}
	if w.pg[w.app("main", "m2")].lsn < last {
		t.Fatal("the new primary is behind the old one's last write")
	}
	// The old primary is stopped by the demote order, restarts as a replica and rejoins.
	if !slices.Contains(w.log, w.app("main", "m1")+" demote ") {
		t.Fatalf("orders: %v", w.log)
	}
	w.settle(6)
	if g.member("m1").Role != pgReplica || !w.write(1) {
		t.Fatalf("m1 %s, writes %v", g.member("m1").Role, w.write(1))
	}
	// A target that is not a replica is refused.
	if err := pgRequestSwitchover(w.st, "db", "", "m2", w.now); err == nil {
		t.Fatal("switchover to the primary")
	}
	if err := pgRequestSwitchover(w.st, "db", "", "m9", w.now); err == nil {
		t.Fatal("switchover to a member that does not exist")
	}
}

func TestPGSwitchoverAbortsWhenTheTargetNeverCatchesUp(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(6)
	w.stalled[w.app("main", "m2")] = true
	w.write(100)
	if err := pgRequestSwitchover(w.st, "db", "", "m2", w.now); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		w.step(5 * time.Second)
	}
	g := w.cluster().group("main")
	if g.Switch != nil || w.primaryOf("main") != "m1" || !strings.Contains(w.events("main"), "aborted") || !w.write(1) {
		t.Fatalf("a stuck switchover must abort and make the primary writable again: %s", w.events("main"))
	}
}

func TestPGAddAndRemoveReplicas(t *testing.T) {
	w := newPGWorld(t, 4)
	w.create(pgCreateOpts{Replicas: 1})
	w.settle(6)
	if err := pgSetReplicas(w.st, "db", 3); err != nil {
		t.Fatal(err)
	}
	w.settle(8)
	g := w.cluster().group("main")
	if len(g.Members) != 4 {
		t.Fatalf("members: %d (%s)", len(g.Members), w.events("main"))
	}
	nodes := map[string]bool{}
	for _, m := range g.Members {
		nodes[m.Node] = true
		if m.Role == pgReplica && !m.Joined {
			t.Fatalf("%s did not join", m.ID)
		}
	}
	if len(nodes) != 4 {
		t.Fatalf("members share nodes: %v", nodes)
	}
	if g.Sync != "ANY 2 (m2, m3, m4)" {
		t.Fatalf("sync after scaling out: %q", g.Sync)
	}
	// The primary was never restarted or told to stop.
	for _, l := range w.log {
		if strings.HasPrefix(l, w.app("main", "m1")+" demote") {
			t.Fatalf("scaling touched the primary: %v", w.log)
		}
	}
	if len(w.st.Apps) != 4 {
		t.Fatalf("apps: %d", len(w.st.Apps))
	}

	// Scaling in: a replica leaves the synchronous set first, its slot is dropped, then it goes.
	if err := pgSetReplicas(w.st, "db", 1); err != nil {
		t.Fatal(err)
	}
	w.settle(12)
	g = w.cluster().group("main")
	if len(g.Members) != 2 || g.Sync != "" {
		t.Fatalf("after scaling in: %d members, sync %q (%s)", len(g.Members), g.Sync, w.events("main"))
	}
	if len(w.st.Apps) != 2 {
		t.Fatalf("apps after scaling in: %d", len(w.st.Apps))
	}
	if len(w.st.PurgeData) != 2 {
		t.Fatalf("the data of removed replicas is purged: %v", w.st.PurgeData)
	}
	dropped := 0
	for _, l := range w.log {
		if strings.Contains(l, " dropslot ziro_") {
			dropped++
		}
	}
	if dropped != 2 {
		t.Fatalf("slots dropped: %d (%v)", dropped, w.log)
	}

	// The CLI paths: add on a chosen node, remove a named member, never the primary.
	if err := pgRemoveReplica(w.st, "db", "", "m1"); err == nil {
		t.Fatal("removing the primary")
	}
	id, err := pgAddReplica(w.st, "db", "", "", "")
	if err != nil || id == "" {
		t.Fatalf("add replica: %q %v", id, err)
	}
	if _, err := pgAddReplica(w.st, "db", "", "n9", ""); err == nil {
		t.Fatal("unknown node")
	}
	if err := pgRemoveReplica(w.st, "db", "", "m99"); err == nil {
		t.Fatal("unknown member")
	}
}

func TestPGReportsFromTheWrongNodeAreIgnored(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(4)
	m := w.member("main", "m2")
	before := m.Probe
	other := "n1"
	if m.Node == other {
		other = "n3"
	}
	pgIngest(w.st, other, []PGReport{{App: w.app("main", "m2"), OK: true, Recovery: true, LSN: "0/FFFF", Timeline: 9}}, nil, w.now.Add(time.Hour))
	if m.Probe != before {
		t.Fatal("a node reported for a member it does not run")
	}
	pgIngest(w.st, m.Node, []PGReport{{App: w.app("main", "m2"), OK: true, LSN: "garbage"}, {App: "web", OK: true, LSN: "0/1"}}, nil, w.now)
	if m.Probe != before {
		t.Fatal("an invalid report was accepted")
	}
	// A report's age counts: an agent whose probes hang must not look healthy.
	now := w.now.Add(time.Hour)
	pgIngest(w.st, m.Node, []PGReport{{App: w.app("main", "m2"), OK: true, Recovery: true, LSN: "0/10", Timeline: 1, AgeMs: 60_000}}, nil, now)
	if m.fresh(now) {
		t.Fatal("a one-minute-old probe is not fresh")
	}
	// A result for another node's order is ignored.
	g := w.cluster().group("main")
	p := g.primary()
	p.Cmd = newPGCommand(opReadonly, "", 0, now)
	pgIngest(w.st, "n-other", nil, []PGResult{{ID: p.Cmd.ID, OK: true}}, now)
	if p.Cmd.Done {
		t.Fatal("an order was completed by a node that does not run the member")
	}
}

func TestPGCommandsAreAClosedList(t *testing.T) {
	for _, tc := range []struct {
		op, arg string
		ok      bool
	}{
		{opPromote, "", true}, {opDemote, "", true}, {opReadonly, "", true}, {opWritable, "", true},
		{opPromote, "x", false},
		{opSetSync, "", true}, {opSetSync, "ANY 1 (m2, m3)", true}, {opSetSync, "ANY 2 (m2, m3, m4)", true},
		{opSetSync, "ANY 1 (m2); drop table x", false}, {opSetSync, "ANY 3 (m2)", false}, {opSetSync, "'; --", false},
		{opSlots, "", true}, {opSlots, "ziro_m2,ziro_m3", true}, {opSlots, "ziro_m2;drop", false}, {opSlots, "Ziro", false},
		{opDropSlot, "ziro_m2", true}, {opDropSlot, "", false}, {opDropSlot, "a'b", false},
		{"exec", "rm -rf /", false}, {"", "", false}, {"sql", "select 1", false},
	} {
		if err := validPGCommand(tc.op, tc.arg); (err == nil) != tc.ok {
			t.Errorf("%s %q: %v", tc.op, tc.arg, err)
		}
	}
}

func TestPGDNSFollowsRoles(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(6)
	eps := podEndpoints(w.st)
	ip := func(id string) string { return memberIP(w.st, w.app("main", id)) }
	if !slices.Equal(eps["db-rw"], []string{ip("m1")}) {
		t.Fatalf("rw: %v", eps["db-rw"])
	}
	want := []string{ip("m2"), ip("m3")}
	slices.Sort(want)
	if !slices.Equal(eps["db-ro"], want) || !slices.Equal(eps["db-main-ro"], want) {
		t.Fatalf("ro: %v want %v", eps["db-ro"], want)
	}
	// A replica that falls behind leaves the read-only name; with none ready, reads go to the primary.
	w.stalled[w.app("main", "m2")] = true
	w.stalled[w.app("main", "m3")] = true
	w.settle(2)
	for _, id := range []string{"m2", "m3"} {
		w.member("main", id).Probe.LagMs = pgReadyLagMillis + 1
	}
	if eps = podEndpoints(w.st); !slices.Equal(eps["db-ro"], []string{ip("m1")}) {
		t.Fatalf("ro with no ready replica: %v", eps["db-ro"])
	}
	// Gateway targets and routing consent follow the aliases.
	if got := pgAliasTargets(eps, w.st, "db-rw"); !slices.Equal(got, []string{ip("m1") + ":5432"}) {
		t.Fatalf("gateway targets: %v", got)
	}
	if pgAliasTargets(eps, w.st, "web") != nil || isPGAlias(w.st, "web") || !isPGAlias(w.st, "db-ro") {
		t.Fatal("alias detection")
	}
	w.st.Routes = []GatewayRoute{{Name: "pg", Kind: "tcp", Listen: 5432, To: []GatewayUpstream{{App: "db-rw", Weight: 1}}}}
	w.st.Nodes[0].Gateway = true
	if got := gatewaySources(w.st, w.app("main", "m2")); len(got) == 0 {
		t.Fatal("the gateway must pass the members' network policy for a routed alias")
	}
	if got := gatewaySources(w.st, "web"); len(got) != 0 {
		t.Fatalf("unrelated app: %v", got)
	}
}

func TestPGDeleteRemovesAppsAndPurgesOnRequest(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(4)
	if err := pgDelete(w.st, "db", true); err != nil {
		t.Fatal(err)
	}
	w.settle(1)
	if len(w.st.Apps) != 0 || w.st.Secrets["pg-db"] != nil || len(w.st.PurgeData) != 3 {
		t.Fatalf("apps %d, secret %v, purge %v", len(w.st.Apps), w.st.Secrets["pg-db"], w.st.PurgeData)
	}
	if err := pgDelete(w.st, "db", false); err == nil {
		t.Fatal("deleting a cluster twice")
	}
	// Without purge the data stays on the nodes.
	w2 := newPGWorld(t, 3)
	w2.create(pgCreateOpts{Replicas: 2})
	w2.settle(4)
	if err := pgDelete(w2.st, "db", false); err != nil {
		t.Fatal(err)
	}
	w2.settle(1)
	if len(w2.st.Apps) != 0 || len(w2.st.PurgeData) != 0 || w2.st.Secrets["pg-db"] == nil {
		t.Fatal("rm without --purge keeps data and credentials")
	}
}

func TestPGPausedClusterIsLeftAlone(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(6)
	w.cluster().Paused = true
	w.down[w.member("main", "m1").Node] = true
	w.step(pgGrace + 10*time.Second)
	w.settle(3)
	if w.primaryOf("main") != "m1" {
		t.Fatal("a paused cluster must not fail over")
	}
}

func TestParseLSN(t *testing.T) {
	for in, want := range map[string]uint64{"0/0": 0, "0/3000060": 0x3000060, "1/0": 1 << 32, "A/FF": 0xA<<32 | 0xFF} {
		got, err := parseLSN(in)
		if err != nil || got != want {
			t.Errorf("parseLSN(%q) = %x, %v", in, got, err)
		}
		if formatLSN(want) != strings.ToUpper(in) {
			t.Errorf("formatLSN(%x) = %s", want, formatLSN(want))
		}
	}
	for _, bad := range []string{"", "3000060", "x/y", "0/", "/1", "0/FFFFFFFFF"} {
		if _, err := parseLSN(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestPGTuning(t *testing.T) {
	conf := pgTuning(&Resources{Memory: "8Gi", CPUs: 4}, false)
	for _, want := range []string{"shared_buffers = 2048MB", "effective_cache_size = 4915MB", "wal_level = replica", "max_parallel_workers = 4", "hot_standby_feedback = on", "max_slot_wal_keep_size = 8GB"} {
		if !strings.Contains(conf, want) {
			t.Errorf("tuning lacks %q:\n%s", want, conf)
		}
	}
	if c := pgTuning(&Resources{Memory: "8Gi"}, true); !strings.Contains(c, "wal_level = logical") || !strings.Contains(c, "max_prepared_transactions") {
		t.Errorf("citus tuning:\n%s", c)
	}
	if c := pgTuning(nil, false); !strings.Contains(c, "shared_buffers = 256MB") {
		t.Errorf("default tuning:\n%s", c)
	}
	if pgTuning(&Resources{Memory: "8Gi", CPUs: 4}, false) != conf {
		t.Fatal("rendering must be deterministic")
	}
}

func TestPGAgentStepsAreFixedTemplates(t *testing.T) {
	c := "zc-pgc-db-main-m1-abcd1234"
	steps, err := pgSteps(PGOrder{Container: c, Op: opSetSync, Arg: "ANY 1 (m2, m3)"})
	if err != nil || len(steps) != 1 || !slices.Contains(steps[0], "alter system set synchronous_standby_names = 'ANY 1 (m2, m3)'") {
		t.Fatalf("setsync: %v %v", steps, err)
	}
	if steps, _ = pgSteps(PGOrder{Container: c, Op: opSetSync}); !slices.Contains(steps[0], "alter system reset synchronous_standby_names") {
		t.Fatalf("async: %v", steps)
	}
	steps, _ = pgSteps(PGOrder{Container: c, Op: opPromote})
	if len(steps) != 2 || steps[0][4] != pgPgCtl || !slices.Contains(steps[0], "promote") || !slices.Contains(steps[1], sqlResetRO) {
		t.Fatalf("promote: %v", steps)
	}
	steps, _ = pgSteps(PGOrder{Container: c, Op: opDemote})
	if len(steps) != 2 || !slices.Contains(steps[0], sqlSetRO) || !slices.Contains(steps[1], "stop") {
		t.Fatalf("demote: %v", steps)
	}
	if _, err := pgSteps(PGOrder{Container: c, Op: opDropSlot, Arg: "x'; drop table y; --"}); err == nil {
		t.Fatal("an injected slot name")
	}
	var ran [][]string
	run := func(_ context.Context, argv ...string) (string, error) { ran = append(ran, argv); return "", nil }
	if err := pgExecute(context.Background(), run, PGOrder{Container: "zc-web-1-abc", Op: opPromote}); err == nil || len(ran) != 0 {
		t.Fatal("an order for a container that is not a member must not run")
	}
	if err := pgExecute(context.Background(), run, PGOrder{Container: c, Op: "exec", Arg: "rm -rf /"}); err == nil || len(ran) != 0 {
		t.Fatal("an unknown order must not run")
	}
	if err := pgExecute(context.Background(), run, PGOrder{Container: c, Op: opReadonly}); err != nil || len(ran) != 1 || ran[0][0] != "exec" {
		t.Fatalf("readonly: %v %v", err, ran)
	}
}

func TestPGProbeParsing(t *testing.T) {
	r, err := parseProbe("0|0/3000060|1|0|0\n")
	if err != nil || r.Recovery || r.LSN != "0/3000060" || r.Timeline != 1 || r.Streaming {
		t.Fatalf("primary: %+v %v", r, err)
	}
	r, err = parseProbe("1|0/3000060|2|1|120")
	if err != nil || !r.Recovery || !r.Streaming || r.LagMs != 120 || r.Timeline != 2 {
		t.Fatalf("replica: %+v %v", r, err)
	}
	for _, bad := range []string{"", "psql: error: connection refused", "2|0/1|1|0|0", "0|nope|1|0|0", "0|0/1|x|0|0", "0|0/1|1|0"} {
		if _, err := parseProbe(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	// A failed probe keeps the last good one with its age.
	calls := 0
	run := func(_ context.Context, argv ...string) (string, error) {
		calls++
		if calls > 1 {
			return "", fmt.Errorf("exit status 2")
		}
		return "0|0/10|1|0|0", nil
	}
	ag := &pgAgent{reports: map[string]pgStamped{}, results: map[string]pgDone{}, seen: map[string]time.Time{}, run: run}
	as := []Assignment{{Name: "zc-pgc-db-main-m1-abc", App: "pgc-db-main-m1", PG: true}, {Name: "zc-web-1-abc", App: "web"}}
	now := time.Now()
	ag.probeAll(context.Background(), as, now)
	ag.probeAll(context.Background(), as, now.Add(8*time.Second))
	reps, _ := ag.report(now.Add(10 * time.Second))
	if len(reps) != 1 || !reps[0].OK || reps[0].AgeMs != 10_000 {
		t.Fatalf("reports: %+v", reps)
	}
}

func TestPGAgentOrdersRunOnceAndReportBack(t *testing.T) {
	var ran int
	run := func(_ context.Context, argv ...string) (string, error) { ran++; return "", nil }
	ag := &pgAgent{reports: map[string]pgStamped{}, results: map[string]pgDone{}, seen: map[string]time.Time{}, run: run}
	o := PGOrder{ID: "o1", App: "pgc-db-main-m1", Container: "zc-pgc-db-main-m1-abc", Op: opReadonly}
	now := time.Now()
	ag.submit(context.Background(), []PGOrder{o, o}, now)
	ag.submit(context.Background(), []PGOrder{o}, now)
	for i := 0; i < 100; i++ {
		ag.mu.Lock()
		n := len(ag.results)
		ag.mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, res := ag.report(time.Now())
	if len(res) != 1 || !res[0].OK || ran != 1 {
		t.Fatalf("results %+v, ran %d", res, ran)
	}
}
