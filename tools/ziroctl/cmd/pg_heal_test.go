package cmd

import (
	"strings"
	"testing"
	"time"
)

// advance moves time forward in the controller's own 5 second passes: a longer jump would make every
// probe look stale when the controller runs.
func (w *pgWorld) advance(d time.Duration) {
	w.t.Helper()
	for ; d > 0; d -= 5 * time.Second {
		w.step(5 * time.Second)
	}
}

func (w *pgWorld) logHas(sub string) bool {
	for _, l := range w.log {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// alertsMatching counts the distinct alert events of group main that contain sub, over a run: the
// event ring keeps only the last few, so they are collected as the run goes.
type alertCounter struct {
	seen map[string]bool
	sub  string
}

func (a *alertCounter) collect(w *pgWorld) {
	if a.seen == nil {
		a.seen = map[string]bool{}
	}
	for _, e := range w.cluster().group("main").Events {
		if e.Alert != "" && strings.Contains(e.Msg, a.sub) {
			a.seen[e.At.String()+e.Msg] = true
		}
	}
}

// A replica that answers but never follows the primary (a lost slot, a diverged timeline) used to stay
// that way forever, counted as a standby. It is rebuilt after ten minutes without progress, once an hour.
func TestPGRebuildsAReplicaThatMakesNoProgress(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	app := w.app("main", "m3")
	w.stalled[app] = true // it answers, but its WAL receiver never connects
	w.settle(2)
	if !contains(w.reasons("main"), "m3 makes no progress; the controller rebuilds it from the primary in") {
		t.Fatalf("the countdown is not shown: %q", w.reasons("main"))
	}
	for i := 0; i < 9; i++ {
		w.advance(time.Minute)
	}
	if w.pg[app].reinits != 0 {
		t.Fatalf("rebuilt after 9 minutes: %s", w.events("main"))
	}
	for i := 0; i < 3; i++ {
		w.advance(time.Minute)
	}
	if w.pg[app].reinits != 1 || !strings.Contains(w.events("main"), "m3 has not followed the primary for 10m0s: rebuilding it from the primary") {
		t.Fatalf("not rebuilt after 12 minutes: reinits=%d %s", w.pg[app].reinits, w.events("main"))
	}
	if w.member("main", "m3").Joined {
		t.Fatal("a rebuilt replica must not count as a standby until it has caught up")
	}
	// still stalled: the rebuild did not fix it, so a second one is left to an operator
	for i := 0; i < 15; i++ {
		w.advance(time.Minute)
	}
	if w.pg[app].reinits != 1 || !strings.Contains(w.events("main"), "was rebuilt less than an hour ago") {
		t.Fatalf("a second rebuild within the hour: reinits=%d %s", w.pg[app].reinits, w.events("main"))
	}
	// the cause goes away: it catches up and the timers are clear
	w.stalled[app] = false
	w.settle(8)
	if m := w.member("main", "m3"); !m.ready(w.now) || !m.UnreadySince.IsZero() || !m.Joined {
		t.Fatalf("m3 after the cause is gone: %+v unready=%v joined=%v", m.Probe, m.UnreadySince, m.Joined)
	}
	if w.primaryOf("main") != "m1" {
		t.Fatalf("healing a replica changed the primary: %s", w.events("main"))
	}
}

// A replica that is behind but gaining is not stuck: a long catch-up is not rebuilt.
func TestPGLongCatchUpIsProgress(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	app := w.app("main", "m3")
	w.stalled[app] = true
	for i := 0; i < 30; i++ {
		w.pg[app].lsn += 1 << 20 // it replays something every minute
		w.advance(time.Minute)
	}
	if w.pg[app].reinits != 0 {
		t.Fatalf("a replica that was gaining was rebuilt: %s", w.events("main"))
	}
}

// A silent replica is a node or container problem, not a data problem: it is not rebuilt.
func TestPGSilentReplicaIsNotRebuilt(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	w.down[w.member("main", "m3").Node] = true
	for i := 0; i < 15; i++ {
		w.advance(time.Minute)
	}
	if w.pg[w.app("main", "m3")].reinits != 0 || w.logHas("reinit") {
		t.Fatalf("a replica on a silent node was rebuilt: %v", w.log)
	}
}

func TestPGCandidateSkipsAReplicaOnAnOlderTimeline(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	probe := func(lsn uint64, tl int) PGProbe {
		return PGProbe{At: now, OK: true, Recovery: true, LSN: lsn, Timeline: tl}
	}
	g := &PGGroup{Members: []PGMember{
		{ID: "m1", Role: pgPrimary, Probe: PGProbe{At: now.Add(-time.Hour), OK: false, Timeline: 3}},
		{ID: "m2", Role: pgReplica, Joined: true, Probe: probe(900, 2)}, // furthest ahead, but on timeline 2
		{ID: "m3", Role: pgReplica, Joined: true, Probe: probe(400, 3)},
		{ID: "m4", Role: pgReplica, Joined: true, Probe: probe(100, 0)}, // timeline unknown (no WAL receiver): not excluded
	}}
	best, reachable, total := pgCandidate(g, now)
	if best == nil || best.ID != "m3" || reachable != 2 || total != 3 {
		t.Fatalf("best=%v reachable=%d total=%d", best, reachable, total)
	}
	// with no primary on record every timeline counts
	g.Members[0].Role = pgFenced
	if best, _, _ := pgCandidate(g, now); best == nil || best.ID != "m2" {
		t.Fatalf("without a known timeline the furthest replica wins: %v", best)
	}
}

// After a promotion the new primary may still carry the synchronous list of its past; "no standbys" is a
// value that must be sent too, or commits wait for replicas that are not there.
func TestPGSyncListIsResentAfterAPromotion(t *testing.T) {
	w := newPGWorld(t, 2)
	w.create(pgCreateOpts{Replicas: 1})
	w.settle(8)
	w.down[w.member("main", "m1").Node] = true
	w.step(pgGrace + 5*time.Second)
	w.settle(8)
	if w.primaryOf("main") != "m2" {
		t.Fatalf("no failover: %s", w.events("main"))
	}
	if !w.logHas(w.app("main", "m2") + " setsync ") {
		t.Fatalf("the synchronous list (empty: no replica is left) was never sent to the new primary: %v", w.log)
	}
	if g := w.cluster().group("main"); g.Sync == pgSyncUnknown {
		t.Fatalf("the list is still unknown: %q", g.Sync)
	}
	if v := pgViewOf(w.st, w.cluster(), w.now); v.Groups[0].Sync == pgSyncUnknown {
		t.Fatal("the placeholder leaked into the status")
	}
}

func TestPGReadOnlyPrimaryIsMadeWritable(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	app := w.app("main", "m1")
	w.pg[app].readonly = true // an aborted switchover left it so
	w.settle(3)
	if w.pg[app].readonly || !w.logHas(app+" writable") {
		t.Fatalf("the primary stayed read-only: %v", w.log)
	}
	if !w.write(10) {
		t.Fatal("the primary does not take writes")
	}
}

// A leader that has just been elected knows no probes: it must not fail anything over before the
// members have had time to report.
func TestPGNoFailoverRightAfterALeaderChange(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	pgProbesUnknown(w.st, w.now) // what a new cluster leader does
	w.down[w.member("main", "m1").Node] = true
	w.step(pgGrace + 5*time.Second)
	w.settle(2)
	if w.primaryOf("main") != "m1" || !contains(w.reasons("main"), "cluster leader changed recently") {
		t.Fatalf("failed over inside the hold (or does not say it waits): %s %q", w.events("main"), w.reasons("main"))
	}
	w.step(pgHoldAfterElection)
	w.settle(4)
	if w.primaryOf("main") == "m1" {
		t.Fatalf("never failed over after the hold: %s", w.events("main"))
	}
}

// Once a primary has been seen serving, its role file says so, and that must not restart the member:
// the file is delivered without touching the app's spec.
func TestPGInitialisedIsInTheRoleFileNotTheSpec(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	m1 := w.member("main", "m1")
	g := w.cluster().group("main")
	if strings.Contains(pgRoleFile(m1, g), "initialised") {
		t.Fatal("initialised before the member has ever served")
	}
	before := specHash(pgMemberApp(w.st, w.cluster(), g, m1))
	w.settle(8)
	if !m1.Initialised || !strings.Contains(pgRoleFile(m1, g), "initialised=1\n") {
		t.Fatalf("a primary that served was not marked: %+v", m1)
	}
	if after := specHash(pgMemberApp(w.st, w.cluster(), g, m1)); after != before {
		t.Fatal("marking a member initialised changes its spec, which would restart the primary")
	}
	for _, id := range []string{"m2", "m3"} {
		if w.member("main", id).Initialised {
			t.Fatalf("%s is a replica", id)
		}
	}
}

func TestPGPersistentCommandFailureAlertsOncePerQuarterHour(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	w.fails[opSlots] = true
	w.member("main", "m1").Cmd = nil
	w.cluster().group("main").Slots = -1 // slots must be (re)created: the order fails every time
	var n alertCounter
	n.sub = "slots on m1 failed"
	for i := 0; i < 180; i++ { // 15 minutes of 5 second passes
		w.step(5 * time.Second)
		n.collect(w)
	}
	if len(n.seen) < 1 || len(n.seen) > 2 {
		t.Fatalf("%d alerts for one failure that repeated for 15 minutes", len(n.seen))
	}
}

func TestPGDrainedMemberLeavesEvenIfTheSyncListCannotBeUpdated(t *testing.T) {
	w := newPGWorld(t, 4)
	w.create(pgCreateOpts{Replicas: 3})
	w.settle(12)
	w.fails[opSetSync] = true
	if err := w.request(func(st *ClusterState, now time.Time) error { return pgSetReplicas(st, "db", 2) }); err != nil {
		t.Fatal(err)
	}
	w.settle(12)
	g := w.cluster().group("main")
	draining := ""
	for _, m := range g.Members {
		if m.Draining {
			draining = m.ID
		}
	}
	if draining == "" {
		t.Fatal("no member is being drained")
	}
	for i := 0; i < 12; i++ {
		w.advance(time.Minute)
	}
	if g.member(draining) != nil {
		t.Fatalf("%s is still in the group after 12 minutes: %s", draining, w.events("main"))
	}
}

func TestPGSaysWhenAMemberOnAGoneNodeCannotBeReplaced(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2}) // every node holds a member: no free node
	w.settle(8)
	gone := w.member("main", "m3").Node
	w.down[gone] = true
	for i := range w.st.Nodes {
		if w.st.Nodes[i].ID == gone {
			w.st.Nodes[i].Status = "NotReady"
		}
	}
	w.step(pgNodeGoneAfter + time.Minute)
	w.settle(4)
	if !strings.Contains(w.events("main"), "no other node is free to rebuild it on") {
		t.Fatalf("a stuck replacement is silent: %s", w.events("main"))
	}
}

func TestParseProbeReadsTheReadOnlyColumnAndAcceptsAnOldAgent(t *testing.T) {
	r, err := parseProbe("0|0/3000060|2|0|0|1\n")
	if err != nil || !r.ReadOnly || r.Recovery || r.Timeline != 2 {
		t.Fatalf("six columns: %+v %v", r, err)
	}
	if r, err := parseProbe("1|0/3000060|2|1|7\n"); err != nil || r.ReadOnly || !r.Recovery || !r.Streaming {
		t.Fatalf("an older agent's five columns: %+v %v", r, err)
	}
	for _, bad := range []string{"0|0/3000060|2|0|0|2", "0|0/3000060|2|0|0|x", "0|0/3000060|2|0", "0|0/3000060|2|0|0|1|1"} {
		if _, err := parseProbe(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
