package cmd

import (
	"strings"
	"testing"
	"time"
)

func (w *pgWorld) request(f func(st *ClusterState, now time.Time) error) error {
	w.t.Helper()
	return f(w.st, w.now)
}

func contains(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func (w *pgWorld) reasons(group string) []string {
	return pgGroupReasons(w.st, w.cluster(), w.cluster().group(group), w.now)
}

// The case that left clusters stuck: two replicas and quorum sync need both to answer before a
// promotion is safe, so with the primary and one replica down nothing was ever promoted, and nothing
// the operator could do.
func TestPGFailoverForceUnsticksAnUnsafeQuorum(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(6)
	w.write(1000)
	w.settle(2)
	w.down[w.member("main", "m1").Node], w.down[w.member("main", "m2").Node] = true, true
	w.step(pgGrace + 5*time.Second)
	w.settle(3)
	if w.primaryOf("main") != "m1" {
		t.Fatalf("promoted although acknowledged writes might be lost: %s", w.events("main"))
	}
	rs := w.reasons("main")
	if !contains(rs, "only 1 of 2 replicas answer") || !contains(rs, "pg failover "+"db"+" --force") {
		t.Fatalf("the status does not say what is wrong or what to do: %q", rs)
	}
	// without --force the safety checks stay
	if err := w.request(func(st *ClusterState, now time.Time) error { return pgRequestFailover(st, "db", "", "", false, now) }); err != nil {
		t.Fatal(err)
	}
	w.settle(2)
	if w.primaryOf("main") != "m1" || !strings.Contains(w.events("main"), "failover refused: only 1 of 2 replicas answer") {
		t.Fatalf("an unforced failover must keep the checks: %s", w.events("main"))
	}
	// with it the replica that answers is promoted
	if err := w.request(func(st *ClusterState, now time.Time) error { return pgRequestFailover(st, "db", "", "", true, now) }); err != nil {
		t.Fatal(err)
	}
	w.settle(3)
	g := w.cluster().group("main")
	if w.primaryOf("main") != "m3" || g.Force != nil || !strings.Contains(w.events("main"), "forced: acknowledged writes may be lost") {
		t.Fatalf("forced failover: primary=%s force=%v %s", w.primaryOf("main"), g.Force, w.events("main"))
	}
}

func TestPGFailoverRefusals(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(6)
	req := func(group, to string, force bool) error {
		return w.request(func(st *ClusterState, now time.Time) error { return pgRequestFailover(st, "db", group, to, force, now) })
	}
	if err := req("", "", false); err == nil || !strings.Contains(err.Error(), "pg switchover") {
		t.Fatalf("a healthy primary must send the operator to switchover: %v", err)
	}
	if err := req("nope", "", false); err == nil {
		t.Fatal("unknown group accepted")
	}
	w.down[w.member("main", "m1").Node] = true
	w.step(pgGrace + 5*time.Second)
	if err := req("", "m1", false); err == nil {
		t.Fatal("the dead primary was accepted as the target")
	}
	if err := req("", "m9", false); err == nil {
		t.Fatal("an unknown member was accepted")
	}
	w.cluster().Paused = true
	if err := req("", "", false); err == nil || !strings.Contains(err.Error(), "paused") {
		t.Fatalf("a paused controller: %v", err)
	}
	w.cluster().Paused = false
	if err := req("", "", false); err != nil {
		t.Fatal(err)
	}
	if err := req("", "", false); err == nil {
		t.Fatal("a second request while one is pending was accepted")
	}
}

// With a partition the controller does not fail over by itself; an operator who knows better can.
func TestPGOperatorFailoverIgnoresThePartitionBrake(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2, Sync: pgSyncOff}) // asynchronous: only the brake stands in the way
	w.settle(8)
	w.down["n1"], w.down["n2"] = true, true // the primary and one replica
	w.step(nodeTimeout + 5*time.Second)
	w.settle(3)
	if w.primaryOf("main") != "m1" {
		t.Fatalf("failed over during a partition: %s", w.events("main"))
	}
	if !contains(w.reasons("main"), "tell a failure from a partition") {
		t.Fatalf("the brake is not explained: %q", w.reasons("main"))
	}
	if err := w.request(func(st *ClusterState, now time.Time) error { return pgRequestFailover(st, "db", "", "", false, now) }); err != nil {
		t.Fatal(err)
	}
	w.settle(3)
	if got := w.primaryOf("main"); got != "m3" {
		t.Fatalf("operator failover during the brake: primary=%s %s", got, w.events("main"))
	}
}

// Asynchronous replication: a replica far behind is not promoted by the controller (it would lose
// those writes), only by an operator who accepts that.
func TestPGLagLimitStopsAutomaticFailoverNotAnOperator(t *testing.T) {
	w := newPGWorld(t, 2)
	w.create(pgCreateOpts{Replicas: 1, Sync: pgSyncOff})
	w.settle(6)
	w.stalled[w.app("main", "m2")] = true // replication stops
	w.write(uint64(pgMaxLagBytes) * 2)
	w.settle(2) // the primary's position is known
	w.down[w.member("main", "m1").Node] = true
	w.step(pgGrace + 5*time.Second)
	w.settle(3)
	if w.primaryOf("main") != "m1" {
		t.Fatalf("promoted a replica %d MiB behind without being told to: %s", 2*pgMaxLagBytes>>20, w.events("main"))
	}
	if !strings.Contains(w.events("main"), "MiB behind the primary's last known position") || !strings.Contains(w.events("main"), "--force") {
		t.Fatalf("the refusal must say why and how to override: %s", w.events("main"))
	}
	if !contains(w.reasons("main"), "MiB behind") {
		t.Fatalf("status reasons: %q", w.reasons("main"))
	}
	if err := w.request(func(st *ClusterState, now time.Time) error { return pgRequestFailover(st, "db", "", "", true, now) }); err != nil {
		t.Fatal(err)
	}
	w.settle(3)
	if w.primaryOf("main") != "m2" {
		t.Fatalf("forced failover: %s", w.events("main"))
	}
	// a replica slightly behind is still promoted automatically
	w2 := newPGWorld(t, 2)
	w2.create(pgCreateOpts{Replicas: 1, Sync: pgSyncOff})
	w2.settle(6)
	w2.write(4096)
	w2.settle(2)
	w2.down[w2.member("main", "m1").Node] = true
	w2.step(pgGrace + 5*time.Second)
	w2.settle(3)
	if w2.primaryOf("main") != "m2" {
		t.Fatalf("a replica within the limit was not promoted: %s", w2.events("main"))
	}
}

func TestPGFailoverRequestExpires(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 1})
	w.settle(6)
	w.down[w.member("main", "m1").Node], w.down[w.member("main", "m2").Node] = true, true // no replica answers
	w.step(pgGrace + 5*time.Second)
	if err := w.request(func(st *ClusterState, now time.Time) error { return pgRequestFailover(st, "db", "", "", true, now) }); err != nil {
		t.Fatal(err)
	}
	w.settle(2)
	if w.cluster().group("main").Force == nil {
		t.Fatal("the request should wait for a replica")
	}
	w.step(3 * time.Minute)
	w.settle(1)
	if w.cluster().group("main").Force != nil || !strings.Contains(w.events("main"), "expired") {
		t.Fatalf("a request nobody can serve must expire: %s", w.events("main"))
	}
}

func TestPGReinitRebuildsAReplicaAndNeverThePrimary(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	w.write(500)
	w.settle(2)
	reinit := func(member string) error {
		return w.request(func(st *ClusterState, now time.Time) error { return pgRequestReinit(st, "db", "", member, now) })
	}
	if err := reinit("m1"); err == nil || !strings.Contains(err.Error(), "only a replica") {
		t.Fatalf("the primary must not be rebuilt: %v", err)
	}
	if err := reinit("m9"); err == nil {
		t.Fatal("unknown member accepted")
	}
	if err := reinit("m2"); err != nil {
		t.Fatal(err)
	}
	if err := reinit("m2"); err == nil || !strings.Contains(err.Error(), "order in progress") {
		t.Fatalf("a second order for the same member: %v", err)
	}
	w.settle(2) // the order runs, then its result is settled
	app := w.app("main", "m2")
	if w.pg[app].reinits != 1 || !strings.Contains(w.events("main"), "m2 is rebuilding from the primary") {
		t.Fatalf("reinit did not run: reinits=%d (%s)", w.pg[app].reinits, w.events("main"))
	}
	w.settle(8)
	if m := w.member("main", "m2"); !m.Joined || !m.ready(w.now) {
		t.Fatalf("the rebuilt replica never caught up: %+v (%s)", m.Probe, w.events("main"))
	}
	if w.primaryOf("main") != "m1" || w.cluster().group("main").Epoch != 0 {
		t.Fatalf("a rebuild must not change the primary: %s", w.events("main"))
	}
	// no primary to copy from: refused
	w.down[w.member("main", "m1").Node] = true
	w.step(pgGrace + 5*time.Second)
	if err := reinit("m3"); err == nil || !strings.Contains(err.Error(), "no answering primary") {
		t.Fatalf("reinit without a primary: %v", err)
	}
}

func TestPGReinitAgentStepsProtectThePrimary(t *testing.T) {
	steps, err := pgSteps(PGOrder{ID: "x", App: "a", Container: "zc-pgc-db-main-m2-1-abc", Op: opReinit, Epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 3 {
		t.Fatalf("steps: %v", steps)
	}
	// the first step fails on a member that is not in recovery, before anything is touched
	if joined := strings.Join(steps[0], " "); !strings.Contains(joined, "1 / (select pg_is_in_recovery()::int)") || !strings.Contains(joined, "ON_ERROR_STOP=1") {
		t.Fatalf("no recovery guard: %s", joined)
	}
	if got := strings.Join(steps[1], " "); !strings.HasSuffix(got, "touch "+pgDataDirIn+"/ziro-reinit") {
		t.Fatalf("marker step: %s", got)
	}
	if steps[2][4] != pgPgCtl || steps[2][5] != "stop" {
		t.Fatalf("stop step: %v", steps[2])
	}
	if _, err := pgSteps(PGOrder{ID: "x", App: "a", Container: "zc-pgc-db-main-m2-1-abc", Op: opReinit, Arg: "x"}); err == nil {
		t.Fatal("reinit takes no argument")
	}
}

func TestPGStatusSaysWhyAGroupIsNotHealthy(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	if r := w.reasons("main"); len(r) != 0 {
		t.Fatalf("a healthy group has reasons: %q", r)
	}
	w.cluster().Paused = true
	v := pgViewOf(w.st, w.cluster(), w.now)
	if !v.Paused || !contains(v.Groups[0].Reasons, "paused") {
		t.Fatalf("a paused cluster must say so: %+v", v.Groups[0].Reasons)
	}
	w.cluster().Paused = false
	w.stalled[w.app("main", "m3")] = true
	w.settle(2)
	if !contains(w.reasons("main"), "m3 is not streaming from the primary") {
		t.Fatalf("a replica that does not stream: %q", w.reasons("main"))
	}
	w.stalled[w.app("main", "m3")] = false
	w.member("main", "m2").Cmd = &PGCommand{ID: "x", Op: opSetSync, At: w.now.Add(-2 * time.Minute), Done: true, Msg: "boom"}
	if !contains(w.reasons("main"), "m2: setsync failed: boom") {
		t.Fatalf("a failed command: %q", w.reasons("main"))
	}
}
