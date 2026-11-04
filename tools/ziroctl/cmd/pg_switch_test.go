package cmd

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A planned switchover fences the primary for as long as it lasts, so it must finish quickly or give up
// quickly, and say what it was waiting for.

func switchWorld(t *testing.T) *pgWorld {
	t.Helper()
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	w.write(100)
	w.step(5 * time.Second) // the replicas replicate it and report
	return w
}

func TestPGSwitchoverRefusesATargetThatCannotCatchUp(t *testing.T) {
	w := switchWorld(t)
	w.stalled[w.app("main", "m2")] = true
	w.step(5 * time.Second) // m2 now reports that it does not stream
	err := pgRequestSwitchover(w.st, "db", "", "m2", w.now)
	if err == nil || !strings.Contains(err.Error(), "m2 is not streaming from the primary") {
		t.Fatalf("a target that does not stream must be refused with the reason: %v", err)
	}
	if w.cluster().group("main").Switch != nil {
		t.Fatal("no switchover was started")
	}
	for _, l := range w.log {
		if strings.Contains(l, " readonly") {
			t.Fatalf("the primary must not be fenced for a switchover that cannot finish: %v", w.log)
		}
	}
}

func TestPGSwitchoverRefusesWhilePaused(t *testing.T) {
	w := switchWorld(t)
	w.cluster().Paused = true
	if err := pgRequestSwitchover(w.st, "db", "", "m2", w.now); err == nil || !strings.Contains(err.Error(), "paused") {
		t.Fatalf("a paused controller takes no steps: %v", err)
	}
}

// The target's probe and the primary's reach the controller on different heartbeats. The target holds
// everything the fenced primary wrote, whenever that was probed, so the switchover must not wait for the two
// probes to line up.
func TestPGSwitchoverDoesNotNeedPairedProbes(t *testing.T) {
	w := switchWorld(t)
	m2 := w.app("main", "m2")
	w.late[m2] = true // its probes stop reaching the controller (they are still fresh for a while)
	if err := pgRequestSwitchover(w.st, "db", "", "m2", w.now); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5 && w.cluster().group("main").Switch != nil; i++ {
		w.step(5 * time.Second)
	}
	if w.cluster().group("main").Switch != nil {
		t.Fatalf("still waiting: %s", pgSwitchWait(w))
	}
	promoted := false
	for _, l := range w.log {
		promoted = promoted || strings.HasPrefix(l, m2+" promote")
	}
	if !promoted {
		t.Fatalf("m2 was not promoted: %v", w.log)
	}
}

func pgSwitchWait(w *pgWorld) string {
	if sw := w.cluster().group("main").Switch; sw != nil {
		return sw.Step + ": " + sw.Wait
	}
	return ""
}

// The readonly order reports the position of the fenced primary; a target that is behind it and stops
// receiving is given up on after pgSwitchStall, not after the whole time.
func TestPGSwitchoverGivesUpWhenTheTargetStopsFollowing(t *testing.T) {
	w := switchWorld(t)
	m1, m2 := w.app("main", "m1"), w.app("main", "m2")
	if err := pgRequestSwitchover(w.st, "db", "", "m2", w.now); err != nil {
		t.Fatal(err)
	}
	start := w.now
	w.stalled[m2] = true    // m2 stops receiving ...
	w.pg[m1].lsn += 1 << 20 // ... the WAL the primary wrote before it was fenced
	for i := 0; i < 30 && w.cluster().group("main").Switch != nil; i++ {
		w.step(5 * time.Second)
	}
	g := w.cluster().group("main")
	if g.Switch != nil {
		t.Fatalf("not given up: %s", pgSwitchWait(w))
	}
	if took := w.now.Sub(start); took > pgSwitchStall+30*time.Second {
		t.Fatalf("gave up after %s: a stalled target must not keep commits blocked for the whole time", took)
	}
	ev := w.events("main")
	if !strings.Contains(ev, "switchover aborted: m2 made no progress for") || !strings.Contains(ev, "in step catchup") || !strings.Contains(ev, "waiting for m2 to receive up to") {
		t.Fatalf("the abort must say who stalled, in which step and what it waited for: %s", ev)
	}
	if w.primaryOf("main") != "m1" {
		t.Fatalf("m1 stays primary, got %s", w.primaryOf("main"))
	}
	writable := false
	for _, l := range w.log {
		writable = writable || strings.HasPrefix(l, m1+" writable ")
	}
	if !writable {
		t.Fatalf("the primary must be made writable again: %v", w.log)
	}
}

// A target that keeps making progress is waited for, up to the limit, and the abort then names the step and
// the numbers.
func TestPGSwitchoverTimeoutNamesTheStepAndWhatItWaitedFor(t *testing.T) {
	w := switchWorld(t)
	m1, m2 := w.app("main", "m1"), w.app("main", "m2")
	if err := pgRequestSwitchover(w.st, "db", "", "m2", w.now); err != nil {
		t.Fatal(err)
	}
	start := w.now
	w.stalled[m2] = true
	w.pg[m1].lsn += 1 << 30 // far more than m2 can receive in the time
	for i := 0; i < 80 && w.cluster().group("main").Switch != nil; i++ {
		w.pg[m2].lsn++ // it creeps forward: never stalled for pgSwitchStall
		w.step(5 * time.Second)
	}
	if w.cluster().group("main").Switch != nil {
		t.Fatal("never given up")
	}
	if took := w.now.Sub(start); took < pgSwitchTimeout || took > pgSwitchTimeout+20*time.Second {
		t.Fatalf("gave up after %s, want about %s", took, pgSwitchTimeout)
	}
	ev := w.events("main")
	if !strings.Contains(ev, "switchover aborted: timed out after 3m") || !strings.Contains(ev, "in step catchup: waiting for m2 to receive up to") {
		t.Fatalf("the timeout must name the step and the wait: %s", ev)
	}
}

func TestPGRollDoesNotRestartASwitchoverRightAfterAnAbort(t *testing.T) {
	w := switchWorld(t)
	c := w.cluster()
	g := c.group("main")
	p := g.primary()
	pending := map[string]bool{p.ID: true}
	g.Notes = map[string]time.Time{pgSwitchAbortedKey: w.now}
	if pgMayRoll(c, g, p, pending, false, w.now) || g.Switch != nil {
		t.Fatalf("a switchover was just given up: the primary is not fenced again at once (switch %+v)", g.Switch)
	}
	w.settle(int(pgSwitchRetryAfter/(5*time.Second)) + 2)
	if pgMayRoll(c, g, g.primary(), pending, false, w.now) || g.Switch == nil {
		t.Fatalf("after the wait the roll hands over to a replica again (switch %+v)", g.Switch)
	}
}

func TestPGSettleKeepsTheLastFailedOrder(t *testing.T) {
	w := switchWorld(t)
	c := w.cluster()
	g := c.group("main")
	m := g.member("m2")
	m.Cmd = &PGCommand{ID: "x", Op: opDropSlot, Done: true, OK: false, Msg: "boom", At: w.now}
	pgSettle(c, g, m, w.now)
	if want := opDropSlot + ": boom"; m.LastFail != want || m.Cmd != nil {
		t.Fatalf("last fail %q, want %q", m.LastFail, want)
	}
	m.Cmd = &PGCommand{ID: "y", Op: opDropSlot, Done: true, OK: true, At: w.now}
	pgSettle(c, g, m, w.now)
	if m.LastFail != "" {
		t.Fatalf("the same order worked since: %q", m.LastFail)
	}
}

func TestPGStatusSaysStartingAndTheLastFailedOrder(t *testing.T) {
	w := switchWorld(t)
	g := w.cluster().group("main")
	g.primary().Probe.LSN += 4096
	m := g.member("m2")
	m.Probe.At = w.now.Add(-time.Minute) // silent
	m.Starting, m.Detail = true, "container running (exit 0)"
	m.LastFail, m.LastFailAt = "reinit: boom", w.now.Add(-time.Minute)
	r := w.reasons("main")
	if !contains(r, "m2 is not answering (Postgres is starting up or replaying WAL after a restart; it answers once it is consistent; container running (exit 0))") {
		t.Fatalf("a member that is starting is not told to be rebuilt: %v", r)
	}
	if !contains(r, "m2: reinit: boom (1m0s ago)") {
		t.Fatalf("the last failed order is shown: %v", r)
	}
	v := pgViewOf(w.st, w.cluster(), w.now)
	for _, mv := range v.Groups[0].Members {
		switch mv.ID {
		case "m2":
			if mv.State != "starting" {
				t.Fatalf("m2 is %s", mv.State)
			}
		case "m3":
			if mv.LagBytes != 4096 {
				t.Fatalf("m3 lag %d bytes", mv.LagBytes)
			}
		}
	}
}

// ---- the agent ----

func TestPGReadonlyOrderReportsThePosition(t *testing.T) {
	c := "zc-pgc-db-main-m1-x"
	steps, _ := pgSteps(PGOrder{Container: c, Op: opReadonly})
	s := strings.Join(steps[0], " ")
	at := func(sub string) int { return strings.Index(s, sub) }
	if !(0 < at(sqlFence) && at(sqlFence) < at(sqlEndClient) && at(sqlEndClient) < at(sqlSettle) && at(sqlSettle) < at(sqlWALPos)) {
		t.Fatalf("fence, end the sessions, let it settle, then read the position: %s", s)
	}
	run := func(context.Context, ...string) (string, error) { return "t\nt\n\n0/B000168\n", nil }
	if msg, err := pgExecuteMsg(context.Background(), run, PGOrder{Container: c, Op: opReadonly}); err != nil || msg != "lsn=0/B000168" {
		t.Fatalf("msg %q err %v", msg, err)
	}
	junk := func(context.Context, ...string) (string, error) { return "t\nwhat\n", nil }
	if msg, err := pgExecuteMsg(context.Background(), junk, PGOrder{Container: c, Op: opReadonly}); err != nil || msg != "" {
		t.Fatalf("an unreadable position is not reported: %q %v", msg, err)
	}
	if got := pgReportedLSN("lsn=0/B000168"); got != 0xB000168 {
		t.Fatalf("lsn %x", got)
	}
	for _, bad := range []string{"", "lsn=", "lsn=zz", "0/B000168"} {
		if pgReportedLSN(bad) != 0 {
			t.Fatalf("read %q", bad)
		}
	}
}

func TestPGAgentSaysWhyAMemberDoesNotAnswer(t *testing.T) {
	var inspects atomic.Int32
	run := func(_ context.Context, argv ...string) (string, error) {
		switch argv[0] {
		case "exec":
			return "psql: error: connection to server on socket failed: FATAL:  the database system is starting up", fmt.Errorf("exit status 2")
		case "inspect":
			inspects.Add(1)
			return "running (exit 0)\n", nil
		case "logs":
			return "LOG:  redo starts at 0/5000028\n", nil
		}
		return "", fmt.Errorf("unexpected %v", argv)
	}
	ag := &pgAgent{reports: map[string]pgStamped{}, results: map[string]pgDone{}, seen: map[string]time.Time{}, run: run}
	var as []Assignment
	for _, m := range []string{"m1", "m2", "m3"} { // probed in parallel
		as = append(as, Assignment{Name: "zc-pgc-db-main-" + m + "-abc", App: "pgc-db-main-" + m, PG: true})
	}
	now := time.Now()
	ag.probeAll(context.Background(), as, now)
	reps, _ := ag.report(now)
	if len(reps) != 3 || inspects.Load() != 3 {
		t.Fatalf("reports %d, inspected %d", len(reps), inspects.Load())
	}
	for _, r := range reps {
		if r.OK || !r.Starting || !strings.Contains(r.Detail, "container running (exit 0)") || !strings.Contains(r.Detail, "redo starts at") {
			t.Fatalf("a member that is starting says so and why: %+v", r)
		}
	}
	ag.probeAll(context.Background(), as, now.Add(5*time.Second))
	if inspects.Load() != 3 {
		t.Fatalf("looked into again after 5 s: %d", inspects.Load())
	}
	ag.probeAll(context.Background(), as, now.Add(pgWhyEvery+time.Second))
	if inspects.Load() != 6 {
		t.Fatalf("not looked into again after %s: %d", pgWhyEvery, inspects.Load())
	}
}

func TestPGAgentKeepsTheProbeErrorOfAMemberThatIsNotStarting(t *testing.T) {
	run := func(_ context.Context, argv ...string) (string, error) {
		switch argv[0] {
		case "exec":
			return "psql: error: connection to server on socket failed: No such file or directory", fmt.Errorf("exit status 2")
		case "inspect":
			return "restarting (exit 1)\n", nil
		}
		return "", fmt.Errorf("no log")
	}
	ag := &pgAgent{reports: map[string]pgStamped{}, results: map[string]pgDone{}, seen: map[string]time.Time{}, run: run}
	now := time.Now()
	ag.probeAll(context.Background(), []Assignment{{Name: "zc-pgc-db-main-m1-abc", App: "pgc-db-main-m1", PG: true}}, now)
	reps, _ := ag.report(now)
	if len(reps) != 1 || reps[0].Starting || !strings.Contains(reps[0].Detail, "container restarting (exit 1)") || !strings.Contains(reps[0].Detail, "(probe: ") {
		t.Fatalf("%+v", reps)
	}
}
