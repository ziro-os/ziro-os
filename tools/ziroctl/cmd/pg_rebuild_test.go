package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A member that a rebuild did not mend is replaced. The group replaces one member at a time; the member
// that has to wait for its turn used to be rebuilt once more, the same way, every hour (the log said
// "left to an operator" and the controller rebuilt it again).

func memberGone(w *pgWorld, id string) bool {
	m := w.member("main", id)
	return m == nil || m.Draining
}

func TestPGDoesNotRebuildTheSameWayTwiceWhileItWaitsForItsTurnToBeReplaced(t *testing.T) {
	w := newPGWorld(t, 6)
	w.create(pgCreateOpts{Replicas: 3})
	w.settle(10)
	a3 := breakReplica(w, "m3")
	a4 := breakReplica(w, "m4")
	w.advance(12 * time.Minute)
	if w.pg[a3].reinits != 1 || w.pg[a4].reinits != 1 {
		t.Fatalf("both are rebuilt once: m3 %d, m4 %d: %s", w.pg[a3].reinits, w.pg[a4].reinits, w.events("main"))
	}
	// An hour on: the first is replaced.
	for i := 0; i < 100 && !memberGone(w, "m3"); i++ {
		w.advance(time.Minute)
	}
	if !memberGone(w, "m3") {
		t.Fatalf("m3 was not replaced: %s", w.events("main"))
	}
	replacedAt := w.now
	// The second has been broken as long, but the group replaces one member at a time: it waits, and is not
	// rebuilt again in the meantime.
	for w.now.Sub(replacedAt) < 50*time.Minute {
		w.advance(time.Minute)
		if memberGone(w, "m4") {
			t.Fatalf("m4 was replaced %s after m3, before the group's turn: %s", w.now.Sub(replacedAt), w.events("main"))
		}
	}
	if w.pg[a4].reinits != 1 {
		t.Fatalf("m4 was rebuilt again the same way (%d rebuilds): %s", w.pg[a4].reinits, w.events("main"))
	}
	ev := w.events("main")
	if !strings.Contains(ev, "m4 still does not work after a rebuild and is not replaced yet: the group replaced a member at") {
		t.Fatalf("the wait is not explained: %s", ev)
	}
	if strings.Contains(ev, "left to an operator") {
		t.Fatalf("the controller does not leave it to an operator: %s", ev)
	}
	// Its turn comes an hour after the first replacement.
	for i := 0; i < 30 && !memberGone(w, "m4"); i++ {
		w.advance(time.Minute)
	}
	if !memberGone(w, "m4") {
		t.Fatalf("m4 was never replaced: %s", w.events("main"))
	}
	if w.pg[a4].reinits != 1 {
		t.Fatalf("m4 was rebuilt again before it was replaced (%d)", w.pg[a4].reinits)
	}
}

// When every replica is broken the fault is not a member's: the primary, the network or the cluster is
// at fault, and replacing members one by one would only churn them.
func TestPGDoesNotReplaceMembersWhenEveryReplicaIsBroken(t *testing.T) {
	w := newPGWorld(t, 5)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	a2 := breakReplica(w, "m2")
	a3 := breakReplica(w, "m3")
	w.advance(80 * time.Minute)
	if memberGone(w, "m2") || memberGone(w, "m3") {
		t.Fatalf("a member was replaced although no replica works: %s", w.events("main"))
	}
	if w.pg[a2].reinits != 1 || w.pg[a3].reinits != 1 {
		t.Fatalf("rebuilt again (m2 %d, m3 %d): %s", w.pg[a2].reinits, w.pg[a3].reinits, w.events("main"))
	}
	if !strings.Contains(w.events("main"), "no other replica is healthy, so the fault may be the primary's or the network's") {
		t.Fatalf("the reason is not given: %s", w.events("main"))
	}
}

// A single replica that is broken is replaced all the same: with no other replica there is nothing to
// compare it with, and the primary answers.
func TestPGReplacesTheOnlyReplicaThatARebuildDidNotMend(t *testing.T) {
	w := newPGWorld(t, 4)
	w.create(pgCreateOpts{Replicas: 1})
	w.settle(8)
	breakReplica(w, "m2")
	for i := 0; i < 120 && !memberGone(w, "m2"); i++ {
		w.advance(time.Minute)
	}
	if !memberGone(w, "m2") {
		t.Fatalf("the only replica was not replaced: %s", w.events("main"))
	}
}

func TestPGAutoRebuildCopiesFromThePrimary(t *testing.T) {
	w := newPGWorld(t, 4)
	w.create(pgCreateOpts{Replicas: 1})
	w.settle(8)
	// A replica added with --from m2 has it in its very first spec (ZIRO_PG_FROM), as a real one does: changing
	// From on a member that is already running would change its spec and roll it, which the rebuild then waits
	// out (pgRollGrace), and the test would be about that instead.
	id, err := pgAddReplica(w.st, "db", "", "", "m2")
	if err != nil {
		t.Fatal(err)
	}
	w.settle(10)
	m := w.member("main", id)
	if m == nil || m.From != "m2" || !m.RolledAt.IsZero() || !m.ready(w.now) {
		t.Fatalf("the replica added with --from m2 is not running as added: %+v (%s)", m, w.events("main"))
	}
	w.stalled[w.app("main", id)] = true
	w.advance(12 * time.Minute)
	if w.pg[w.app("main", id)].reinits != 1 {
		t.Fatalf("not rebuilt: %s", w.events("main"))
	}
	if got := w.member("main", id).From; got != "" {
		t.Fatalf("the rebuild still copies from %q, which may be the problem", got)
	}
}

func TestPGAgentReinitSaysWhenTheRestartFailed(t *testing.T) {
	withDataRoot(t)
	o := PGOrder{ID: "1", App: "pgc-db-main-m3", Container: "zc-pgc-db-main-m3-0-abc", Op: opReinit, Index: 0}
	dir := filepath.Join(dataDir(o.App, o.Index, pgDataPath), "pgdata")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	stuck := func(ctx context.Context, argv ...string) (string, error) {
		if argv[0] == "restart" {
			return "FATA[0000] shim is not responding", errors.New("exit status 1")
		}
		return "Error: container is not running", errors.New("exit status 1")
	}
	err := pgExecute(context.Background(), stuck, o)
	if err == nil || !strings.Contains(err.Error(), "restarting zc-pgc-db-main-m3-0-abc failed") {
		t.Fatalf("a container that cannot be restarted is not rebuilding: %v", err)
	}
	// A container that does not exist yet starts with the marker in place: not a failure.
	absent := func(ctx context.Context, argv ...string) (string, error) {
		if argv[0] == "restart" {
			return "Error: no such container: zc-pgc-db-main-m3-0-abc", errors.New("exit status 1")
		}
		return "Error: no such container", errors.New("exit status 1")
	}
	if err := pgExecute(context.Background(), absent, o); err != nil {
		t.Fatalf("a member whose container does not exist yet is rebuilt when it starts: %v", err)
	}
}
