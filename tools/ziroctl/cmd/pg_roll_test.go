package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// A rolling restart must not make replicas look dead or release the next member too early, and a host reboot
// must not leave the databases to replay WAL for minutes.

func rollRevisions(w *pgWorld) map[string]int {
	out := map[string]int{}
	for _, id := range []string{"m1", "m2", "m3"} {
		out[id] = w.st.app(w.app("main", id)).Revision
	}
	return out
}

// stepUntilRolled steps until one more member has taken the new spec and returns it ("" if none did).
func stepUntilRolled(w *pgWorld, before map[string]int, skip string, max time.Duration) string {
	for waited := time.Duration(0); waited < max; waited += 5 * time.Second {
		w.step(5 * time.Second)
		for id, r := range rollRevisions(w) {
			if r != before[id] && id != skip {
				return id
			}
		}
	}
	return ""
}

// A probe taken after the spec was set can come from the old container, which answers until the node stops
// it. The next member went at once (the probe was newer than the roll); now it waits for the new server.
func TestPGRollWaitsForTheNewServerNotTheOldContainer(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(10)
	for _, id := range []string{"m1", "m2", "m3"} {
		w.started[w.app("main", id)] = w.now // every server reports how long it has been up
	}
	before := rollRevisions(w)
	w.cluster().Resources = &Resources{Memory: "2Gi"}
	first := stepUntilRolled(w, before, "", time.Minute)
	if first == "" || first == "m1" {
		t.Fatalf("a replica goes first, not %q: %s", first, w.events("main"))
	}
	// The old container keeps answering for a while: the next member waits, however many probes arrive.
	if second := stepUntilRolled(w, before, first, 5*time.Minute); second != "" {
		t.Fatalf("%s took the new spec while %s was still the old server: %s", second, first, w.events("main"))
	}
	// Its new server starts: the next one goes.
	w.started[w.app("main", first)] = w.now
	w.settle(2)
	if second := stepUntilRolled(w, before, first, time.Minute); second == "" {
		t.Fatalf("the next member did not go after %s restarted: %s", first, w.events("main"))
	}
}

// An agent that is not upgraded yet does not report the uptime: the probe's time decides, as it did.
func TestPGRollWithoutUptimeFallsBackToTheProbeTime(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(10)
	before := rollRevisions(w)
	w.cluster().Resources = &Resources{Memory: "2Gi"}
	first := stepUntilRolled(w, before, "", time.Minute)
	if first == "" {
		t.Fatalf("no member rolled: %s", w.events("main"))
	}
	if second := stepUntilRolled(w, before, first, time.Minute); second == "" {
		t.Fatalf("a member whose agent reports no uptime holds the roll up: %s", w.events("main"))
	}
}

// A replica that has streamed but is far behind is not "back": the next replica must not go while it still has a
// lot of WAL to replay.
func TestPGRollWaitsForTheReplicaToCatchUp(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	primary := &PGMember{ID: "m1", Role: pgPrimary, Probe: PGProbe{OK: true, At: now, LSN: 100 << 20}}
	replica := func(lsn uint64) *PGMember {
		return &PGMember{ID: "m2", Role: pgReplica, RolledAt: now.Add(-time.Minute),
			Probe: PGProbe{OK: true, At: now, Recovery: true, Streaming: true, LSN: lsn, Started: now.Add(-30 * time.Second)}}
	}
	if pgBack(replica(100<<20-8<<20), primary, now) != true {
		t.Fatal("a replica 8 MiB behind is back")
	}
	if pgBack(replica(60<<20), primary, now) {
		t.Fatal("a replica 40 MiB behind is not back, although it streams and reports 0 ms of lag")
	}
	if !pgBack(replica(60<<20), nil, now) {
		t.Fatal("with no primary to compare with, streaming is all there is to go by")
	}
}

func TestPGRestartedBelievesOnlyAServerStartedAfterTheRoll(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	m := &PGMember{RolledAt: now.Add(-time.Minute), Probe: PGProbe{OK: true, At: now}}
	for _, c := range []struct {
		started time.Time
		want    bool
		why     string
	}{
		{now.Add(-time.Hour), false, "the old server, up for an hour"},
		{now.Add(-30 * time.Second), true, "a server that started after the roll"},
		{time.Time{}, true, "no uptime reported: the probe's time stands"},
	} {
		m.Probe.Started = c.started
		if got := pgRestarted(m, now); got != c.want {
			t.Errorf("%s: %v", c.why, got)
		}
	}
	m.Probe.At = now.Add(-2 * time.Minute) // a probe from before the roll is never proof
	m.Probe.Started = time.Time{}
	if pgRestarted(m, now) {
		t.Error("a probe from before the roll is proof of a restart")
	}
	if !pgRestarted(m, now.Add(pgRollTimeout+time.Minute)) {
		t.Error("the roll waits for ever for a member that never comes back")
	}
}

// A replica that was restarted for a new spec is not advertised until its new server answers: its last probe,
// up to 20 s old, comes from the container that is gone.
func TestPGReadOnlyNameDoesNotAdvertiseAReplicaThatHasNotRestarted(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(10)
	for i := range w.st.Replicas {
		w.st.Replicas[i].IP = fmt.Sprintf("10.200.0.%d", i+1)
	}
	c := w.cluster()
	g := c.group("main")
	m := g.member("m2")
	ro := func() []string { _, ro := pgGroupEndpoints(w.st, c, g, w.now); return ro }
	if len(ro()) != 2 {
		t.Fatalf("both replicas are advertised: %v", ro())
	}
	m.RolledAt = w.now.Add(-5 * time.Second) // it took a new spec a moment ago ...
	m.Probe.At = w.now                       // ... and the latest probe is newer than that
	m.Probe.Started = w.now.Add(-time.Hour)  // ... but from the server that is stopping
	if got := ro(); len(got) != 1 {
		t.Fatalf("a replica that has not restarted is advertised: %v", got)
	}
	m.Probe.Started = w.now.Add(-time.Second) // the new server answers
	if got := ro(); len(got) != 2 {
		t.Fatalf("a restarted replica is not advertised: %v", got)
	}
}

// A new cluster leader has no probes: every member looks down, and a member that is not serving anyway restarts
// at once, the primary in place. It waits until the members have reported.
func TestPGNoRollWhileTheLeaderHasNoProbes(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(10)
	before := rollRevisions(w)
	w.cluster().Resources = &Resources{Memory: "2Gi"}
	w.st.PGHold = w.now.Add(time.Minute)
	for i := 0; i < 8; i++ {
		w.step(5 * time.Second)
	}
	if got := rollRevisions(w); fmt.Sprint(got) != fmt.Sprint(before) {
		t.Fatalf("a member took the new spec while the cluster leader waits for probes: %v -> %v", before, got)
	}
	if first := stepUntilRolled(w, before, "", 2*time.Minute); first == "" {
		t.Fatalf("nothing rolled after the hold: %s", w.events("main"))
	}
}

// A replica whose Postgres is up and replaying WAL (after a reboot) is not rebuilt at 10 minutes, which throws that
// work away and starts a full copy; it is given 30.
func TestPGDoesNotRebuildAReplicaThatIsStillStarting(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	app := w.app("main", "m3")
	w.starting[app] = true
	breakReplica(w, "m3")
	w.advance(20 * time.Minute)
	if w.pg[app].reinits != 0 {
		t.Fatalf("a replica that is replaying WAL was rebuilt: %s", w.events("main"))
	}
	if !contains(w.reasons("main"), "m3 is not answering (Postgres is starting up") {
		t.Fatalf("status does not say it is starting: %q", w.reasons("main"))
	}
	w.advance(15 * time.Minute)
	if w.pg[app].reinits != 1 {
		t.Fatalf("a replica that is 'starting' for ever is never rebuilt: %s", w.events("main"))
	}
}

// A member that restarted for a new spec a moment ago is recovering from the stop, which is not "no progress".
func TestPGDoesNotRebuildAMemberThatJustRestartedForANewSpec(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	app := w.app("main", "m3")
	breakReplica(w, "m3")
	w.member("main", "m3").RolledAt = w.now
	w.advance(25 * time.Minute)
	if w.pg[app].reinits != 0 {
		t.Fatalf("a member was rebuilt within %s of its restart: %s", pgRollGrace, w.events("main"))
	}
	w.advance(10 * time.Minute)
	if w.pg[app].reinits != 1 {
		t.Fatalf("a member that does not come back after a restart is never rebuilt: %s", w.events("main"))
	}
}

// ---- the probe ----

func TestPGProbeReportsHowLongTheServerHasBeenUp(t *testing.T) {
	r, err := parseProbe("1|0/3000060|2|1|120|0|0/3000060||5|200|10|3|0|-1|7200")
	if err != nil || r.UpSecs != 7200 {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err = parseProbe("1|0/3000060|2|1|120|0|0/3000060||5|200|10|3|0|-1"); err != nil || r.UpSecs != 0 {
		t.Fatalf("a probe without the uptime (an older agent): %+v %v", r, err)
	}
	if _, err = parseProbe("1|0/3000060|2|1|120|0|0/3000060||5|200|10|3|0|-1|-5"); err == nil {
		t.Fatal("a negative uptime was accepted")
	}
	if !strings.Contains(pgProbeSQL, "pg_postmaster_start_time()") {
		t.Fatal("the probe does not ask when the server started")
	}
	st := &ClusterState{PG: map[string]*PGCluster{"db": {Name: "db", Groups: []PGGroup{{Name: "main", Members: []PGMember{{ID: "m1", Node: "n1"}}}}}}}
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	pgIngest(st, "n1", []PGReport{{App: "pgc-db-main-m1", OK: true, LSN: "0/10", Timeline: 1, UpSecs: 90, AgeMs: 2000}}, nil, now)
	m := &st.PG["db"].Groups[0].Members[0]
	if want := now.Add(-92 * time.Second); !m.Probe.Started.Equal(want) {
		t.Fatalf("started %v, want %v (up 90 s at a probe taken 2 s ago)", m.Probe.Started, want)
	}
}

// ---- reboot ----

func TestPGMemberContainerIsAMemberNotThePooler(t *testing.T) {
	for name, want := range map[string]bool{
		"zc-pgc-shop-main-m1-0-0123abcd":  true,
		"zc-pgc-shop-coord-m2-0-0123abcd": true,
		"zc-pgc-shop-w3-m1-0-0123abcd":    true,
		"zc-pgc-shop-pool-0-0123abcd":     false, // PgBouncer
		"zc-web-0-0123abcd":               false,
		"zc-pgc-shop-main-m1":             false,
		"pgc-shop-main-m1-0-0123abcd":     false,
	} {
		if got := pgMemberContainer(name); got != want {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
}

func TestPGStopLocalAsksEachMemberForAFastShutdownAndWaits(t *testing.T) {
	var asked []string
	run := func(_ context.Context, argv ...string) (string, error) {
		switch argv[0] {
		case "ps":
			return "zc-web-0-aaaa\nzc-pgc-shop-main-m1-0-aaaa\nzc-pgc-shop-pool-0-bbbb\nzc-pgc-shop-main-m2-0-cccc\nzc-pgc-shop-main-m3-0-dddd\n", nil
		case "inspect":
			asked = append(asked, argv[3])
			switch argv[3] {
			case "zc-pgc-shop-main-m1-0-aaaa":
				return "4242\n", nil
			case "zc-pgc-shop-main-m2-0-cccc":
				return "4343\n", nil
			}
			return "0\n", nil // m3 is not running
		}
		return "", errors.New("unexpected " + argv[0])
	}
	var signalled []int
	signal := func(pid int) error { signalled = append(signalled, pid); return nil }
	alive := map[int]int{4242: 2, 4343: 1000000} // m1 exits after two looks; m2 never does
	look := func(pid int) bool { alive[pid]--; return alive[pid] > 0 }
	lines := pgStopLocal(context.Background(), run, signal, look, 30*time.Millisecond, time.Millisecond)
	out := strings.Join(lines, "\n")
	if fmt.Sprint(signalled) != "[4242 4343]" {
		t.Fatalf("signalled %v: only the members, not the pooler or another app", signalled)
	}
	for _, name := range asked {
		if !pgMemberContainer(name) {
			t.Fatalf("looked into %s", name)
		}
	}
	if !strings.Contains(out, "zc-pgc-shop-main-m1-0-aaaa: shut down cleanly") || !strings.Contains(out, "zc-pgc-shop-main-m3-0-dddd: not running") ||
		!strings.Contains(out, "zc-pgc-shop-main-m2-0-cccc: still running after 30ms: left to init") {
		t.Fatalf("report:\n%s", out)
	}
}

func TestPGStopLocalIsQuietWithoutMembersOrARuntime(t *testing.T) {
	none := func(context.Context, ...string) (string, error) { return "zc-web-0-aaaa\n", nil }
	if lines := pgStopLocal(context.Background(), none, nil, nil, time.Second, time.Millisecond); len(lines) != 1 || lines[0] != pgNoMembersHere {
		t.Fatalf("%v", lines)
	}
	down := func(context.Context, ...string) (string, error) {
		return "FATA[0000] cannot connect to containerd", errors.New("exit status 1")
	}
	if lines := pgStopLocal(context.Background(), down, nil, nil, time.Second, time.Millisecond); len(lines) != 1 || !strings.HasPrefix(lines[0], "no Postgres members stopped:") {
		t.Fatalf("%v", lines)
	}
}

// ---- smaller changes ----

func TestPGPullIsSkippedForAPinnedImageThatIsHere(t *testing.T) {
	ctx := context.Background()
	here := func(context.Context, string) error { return nil }
	gone := func(context.Context, string) error { return errors.New("no such image") }
	pinned := "ghcr.io/ziro-os/postgres:17-pgbackrest@sha256:" + strings.Repeat("a", 64)
	if pullNeeded(ctx, pinned, here) {
		t.Error("a pinned image that is here is pulled again")
	}
	if !pullNeeded(ctx, pinned, gone) {
		t.Error("a pinned image that is not here is not pulled")
	}
	if !pullNeeded(ctx, "docker.io/library/nginx:latest", here) {
		t.Error("a tag can move: it is always pulled")
	}
}

func TestPGTuningSyncsTheVolumeOnceAfterACrash(t *testing.T) {
	if got := pgTuning(nil, false, "17"); !strings.Contains(got, "recovery_init_sync_method = syncfs\n") {
		t.Fatalf("a crashed member fsyncs every file before it recovers:\n%s", got)
	}
}
