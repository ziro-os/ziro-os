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

// A replica whose container does not come up (a crash loop, a data directory Postgres cannot use) never
// answered a probe, so nothing could rebuild it: reinit refused, the automatic rebuild only looked at
// members that answer, and status said "not answering" and no more.

func breakReplica(w *pgWorld, id string) string {
	app := w.app("main", id)
	w.broken[app] = true
	w.advance(40 * time.Second) // its last probe goes stale
	return app
}

func TestPGReinitAndStatusForAReplicaThatDoesNotAnswer(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	app := breakReplica(w, "m3")
	r := w.reasons("main")
	if !contains(r, "m3 is not answering (container running (exit 1): the data directory is not usable; ziroctl pg reinit db m3 rebuilds it)") {
		t.Fatalf("the cause is not shown: %q", r)
	}
	if err := w.request(func(st *ClusterState, now time.Time) error { return pgRequestReinit(st, "db", "", "m3", now) }); err != nil {
		t.Fatalf("reinit of a member that does not answer: %v", err)
	}
	w.settle(2)
	if w.pg[app].reinits != 1 {
		t.Fatalf("the rebuild was not carried out: %s", w.events("main"))
	}
}

func TestPGRebuildsAReplicaWhoseContainerDoesNotComeUp(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	w.rebuildFixes = true
	app := breakReplica(w, "m3")
	w.advance(8 * time.Minute)
	if w.pg[app].reinits != 0 {
		t.Fatalf("rebuilt too early: %s", w.events("main"))
	}
	w.advance(4 * time.Minute)
	if w.pg[app].reinits != 1 || !strings.Contains(w.events("main"), "m3 has not followed the primary for 10m0s") {
		t.Fatalf("not rebuilt: reinits=%d %s", w.pg[app].reinits, w.events("main"))
	}
	w.advance(time.Minute)
	if !w.member("main", "m3").ready(w.now) {
		t.Fatalf("the rebuilt replica did not come back: %s", w.events("main"))
	}
}

func TestPGReplacesAMemberThatARebuildDidNotMend(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	app := breakReplica(w, "m3")
	w.advance(12 * time.Minute)
	if w.pg[app].reinits != 1 {
		t.Fatalf("not rebuilt: %s", w.events("main"))
	}
	for i := 0; i < 90 && w.member("main", "m3") != nil; i++ {
		w.advance(time.Minute)
	}
	if w.member("main", "m3") != nil {
		t.Fatalf("the member that stays broken was not replaced: %s", w.events("main"))
	}
	w.advance(5 * time.Minute)
	if m := w.member("main", "m4"); m == nil || !m.ready(w.now) {
		t.Fatalf("no new member took its place: %s", w.events("main"))
	}
}

func TestPGDoesNotRebuildAMemberThatIsCopying(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	app := w.app("main", "m3")
	w.busy[app] = true
	w.advance(40 * time.Second)
	if r := w.reasons("main"); !contains(r, "m3 is not answering (copying the primary's data") {
		t.Fatalf("a copy in progress is not shown: %q", r)
	}
	w.advance(40 * time.Minute)
	if w.pg[app].reinits != 0 {
		t.Fatalf("a base backup that is running was interrupted: %s", w.events("main"))
	}
}

func TestPGDownNodeIsNotRebuiltOnThePrimary(t *testing.T) {
	w := newPGWorld(t, 4)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	app := w.app("main", "m3")
	w.down[w.member("main", "m3").Node] = true
	w.advance(20 * time.Minute)
	if w.pg[app].reinits != 0 {
		t.Fatalf("a replica on a node that is down was rebuilt: %s", w.events("main"))
	}
	if w.member("main", "m3") != nil && !w.member("main", "m3").Draining {
		t.Fatalf("a member on a node that is gone was not replaced: %s", w.events("main"))
	}
}

func withDataRoot(t *testing.T) string {
	t.Helper()
	old := appDataRoot
	appDataRoot = t.TempDir()
	t.Cleanup(func() { appDataRoot = old })
	return appDataRoot
}

func TestPGAgentReinitWithoutAContainer(t *testing.T) {
	withDataRoot(t)
	o := PGOrder{ID: "1", App: "pgc-db-main-m3", Container: "zc-pgc-db-main-m3-0-abc", Op: opReinit, Index: 0}
	dir := filepath.Join(dataDir(o.App, o.Index, pgDataPath), "pgdata")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	var calls []string
	down := func(ctx context.Context, argv ...string) (string, error) {
		calls = append(calls, argv[0])
		if argv[0] == "restart" {
			return "", nil
		}
		return "Error: container is not running", errors.New("exit status 1")
	}
	if err := pgExecute(context.Background(), down, o); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ziro-reinit")); err != nil {
		t.Fatalf("no marker on the data directory: %v", err)
	}
	if calls[len(calls)-1] != "restart" {
		t.Fatalf("the container was not restarted: %v", calls)
	}
}

func TestPGAgentReinitNeverWipesAPrimary(t *testing.T) {
	withDataRoot(t)
	o := PGOrder{ID: "1", App: "pgc-db-main-m1", Container: "zc-pgc-db-main-m1-0-abc", Op: opReinit}
	dir := filepath.Join(dataDir(o.App, o.Index, pgDataPath), "pgdata")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	primary := func(ctx context.Context, argv ...string) (string, error) {
		return "ERROR:  division by zero", errors.New("exit status 1")
	}
	if err := pgExecute(context.Background(), primary, o); err == nil || !strings.Contains(err.Error(), "never rebuilt") {
		t.Fatalf("a primary was accepted for a rebuild: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ziro-reinit")); err == nil {
		t.Fatal("a marker was left on a primary's data directory")
	}
}

func TestPGWhyReportsTheContainerAndTheLastError(t *testing.T) {
	withDataRoot(t)
	a := Assignment{Name: "zc-pgc-db-main-m2-0-abc", App: "pgc-db-main-m2"}
	dir := dataDir(a.App, a.Replica, pgDataPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	run := func(ctx context.Context, argv ...string) (string, error) {
		if argv[0] == "inspect" {
			return "restarting (exit 1)\n", nil
		}
		return "FATAL: could not open file\n", nil
	}
	now := time.Now()
	if d, busy := pgWhy(context.Background(), run, a, now); busy || d != "container restarting (exit 1): FATAL: could not open file" {
		t.Fatalf("detail %q busy=%v", d, busy)
	}
	os.WriteFile(filepath.Join(dir, "ziro-last-error"), []byte("no primary at db-main-rw.cluster.ziro yet\n"), 0600)
	os.WriteFile(filepath.Join(dir, "ziro-busy"), nil, 0600)
	if d, busy := pgWhy(context.Background(), run, a, now); !busy || d != "container restarting (exit 1): no primary at db-main-rw.cluster.ziro yet" {
		t.Fatalf("detail %q busy=%v", d, busy)
	}
	if _, busy := pgWhy(context.Background(), run, a, now.Add(2*time.Minute)); busy {
		t.Fatal("a copy that stopped touching its file is still busy")
	}
}
