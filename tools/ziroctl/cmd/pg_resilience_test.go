package cmd

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"slices"
	"strings"
	"testing"
	"time"
)

// The lease ends before the master fails the primary over, so an old primary has stopped acknowledging
// writes when a replica is promoted (pg_lease.go).
func TestPGLeaseEndsBeforeFailover(t *testing.T) {
	if pgGrace < pgLeaseFresh+pgLeaseTTL+pgLeaseMargin {
		t.Fatalf("grace %s must exceed fresh %s + ttl %s + margin %s", pgGrace, pgLeaseFresh, pgLeaseTTL, pgLeaseMargin)
	}
	if pgLeaseTTL <= 10*time.Second+5*time.Second {
		t.Fatal("a lease must outlast one missed heartbeat (10 s) and a probe interval")
	}
}

func TestPGLeaseGrants(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	fresh := PGProbe{At: now.Add(-3 * time.Second), OK: true}
	g := &PGGroup{Epoch: 4, Members: []PGMember{{ID: "m1", Role: pgPrimary, Probe: fresh}, {ID: "m2", Role: pgReplica, Probe: PGProbe{At: fresh.At, OK: true, Recovery: true}}}}
	if got := pgLeaseFile(g, &g.Members[0], now); got != "grant=1\nttl=22\nepoch=4\nfence=1\n" {
		t.Fatalf("primary: %q", got)
	}
	for name, m := range map[string]PGMember{
		"stale probe (a hung container runtime)":   {Role: pgPrimary, Probe: PGProbe{At: now.Add(-8 * time.Second), OK: true}},
		"fenced former primary":                    {Role: pgFenced, Probe: fresh},
		"a replica out of recovery nobody elected": {Role: pgReplica, Probe: fresh},
		"probe failed":                             {Role: pgPrimary, Probe: PGProbe{At: now, OK: false}},
	} {
		if pgLeaseGrant(&m, now) {
			t.Errorf("%s: granted", name)
		}
	}
	if !pgLeaseGrant(&g.Members[1], now) {
		t.Fatal("a replica in recovery gets a lease (it may be promoted)")
	}
	single := &PGGroup{Members: []PGMember{{ID: "m1", Role: pgPrimary, Probe: fresh}}}
	if got := pgLeaseFile(single, &single.Members[0], now); !strings.Contains(got, "fence=0") {
		t.Fatalf("a group with nothing to fail over to is not fenced: %q", got)
	}
	if grant, ttl, epoch := parseLeaseFile("grant=1\nttl=22\nepoch=4\nfence=1\nfuture=x\n"); !grant || ttl != 22*time.Second || epoch != 4 {
		t.Fatalf("parse: %v %v %v", grant, ttl, epoch)
	}
	if _, ttl, _ := parseLeaseFile("grant=1\nttl=99999\n"); ttl != 0 {
		t.Fatal("an absurd ttl is refused")
	}
}

func TestPGAgentRefusesOrdersFromAnOlderEpoch(t *testing.T) {
	var ran []string
	run := func(_ context.Context, argv ...string) (string, error) {
		ran = append(ran, strings.Join(argv, " "))
		return "", nil
	}
	ag := newPGAgent()
	ag.run = run
	app, ctr := "pgc-db-main-m1", "zc-pgc-db-main-m1-abc"
	now := time.Now()
	ag.submit(context.Background(), []PGOrder{{ID: "new", App: app, Container: ctr, Op: opWritable, Epoch: 3}}, now)
	ag.submit(context.Background(), []PGOrder{{ID: "old", App: app, Container: ctr, Op: opPromote, Epoch: 2}}, now)
	for i := 0; i < 100; i++ {
		ag.mu.Lock()
		n := len(ag.results)
		ag.mu.Unlock()
		if n == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, res := ag.report(time.Now())
	byID := map[string]PGResult{}
	for _, r := range res {
		byID[r.ID] = r
	}
	if !byID["new"].OK || byID["old"].OK || !strings.Contains(byID["old"].Msg, "older") {
		t.Fatalf("results: %+v", res)
	}
	for _, r := range ran {
		if strings.Contains(r, "promote") {
			t.Fatal("the stale promotion ran")
		}
	}
}

func TestPGProbeReadsReceivedWALAndStandbys(t *testing.T) {
	r, err := parseProbe("1|0/3000060|2|1|0|0|0/3000F00|ANY 1 (m1, m3)")
	if err != nil || r.Received != "0/3000F00" || r.SyncNames != "ANY 1 (m1, m3)" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := parseProbe("1|0/3000060|2|1|0|0"); err != nil || r.Received != "0/3000060" {
		t.Fatalf("an older agent's probe: %+v %v", r, err)
	}
	if _, err := parseProbe("1|0/3000060|2|1|0|0|junk|x"); err == nil {
		t.Fatal("a bad received position is refused")
	}
}

func TestPGCandidateIsTheReplicaHoldingTheMostWAL(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	p := func(lsn, rcv uint64) PGProbe {
		return PGProbe{At: now, OK: true, Recovery: true, LSN: lsn, Received: rcv, Timeline: 1}
	}
	g := &PGGroup{Members: []PGMember{
		{ID: "m1", Role: pgPrimary, Probe: PGProbe{At: now.Add(-time.Minute), OK: true, LSN: 900, Timeline: 1}},
		{ID: "m2", Role: pgReplica, Joined: true, Probe: p(800, 800)},
		{ID: "m3", Role: pgReplica, Joined: true, Probe: p(700, 850)}, // replayed less, but received more
	}}
	if best, _, _ := pgCandidate(g, now); best == nil || best.ID != "m3" {
		t.Fatalf("best %v: the replica that received an acknowledged commit must win", best)
	}
}

func TestPGReplicaOnAnOlderTimelineDoesNotServe(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(6)
	m3 := w.member("main", "m3")
	if !m3.ready(w.now) {
		t.Fatal("m3 should be ready")
	}
	w.pg[w.app("main", "m1")].tli = 3 // the primary moved on; m3 is stuck on timeline 1
	w.stalled[w.app("main", "m3")] = true
	w.settle(2)
	if !m3.OffTimeline || m3.ready(w.now) {
		t.Fatalf("m3 on an older timeline: off=%v ready=%v", m3.OffTimeline, m3.ready(w.now))
	}
	// ready() is what puts a replica behind the read-only name (pgGroupEndpoints)
}

func TestPGReplicasFollowThePrimaryByName(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	want := "host=1." + w.app("main", "m1") + ".cluster.ziro port=5432 user=replicator application_name=m2 sslmode=verify-ca sslrootcert=/var/lib/postgresql/data/ziro-tls/ca.crt"
	if m2 := w.member("main", "m2"); m2.Following != want {
		t.Fatalf("m2 follows %q, want %q", m2.Following, want)
	}
	// the primary's node goes: after the promotion, the remaining replica is pointed at the new primary
	w.down[w.member("main", "m1").Node] = true
	for i := 0; i < 30 && w.cluster().group("main").primary() != nil && w.primaryOf("main") == "m1"; i++ {
		w.step(5 * time.Second)
	}
	w.settle(4)
	np := w.primaryOf("main")
	other := map[string]string{"m2": "m3", "m3": "m2"}[np]
	if np == "m1" || other == "" {
		t.Fatalf("no failover: %s (%s)", np, w.events("main"))
	}
	if f := w.member("main", other).Following; !strings.Contains(f, "host=1."+w.app("main", np)+".") {
		t.Fatalf("%s follows %q after %s was promoted", other, f, np)
	}
	if !strings.Contains(pgRoleFile(w.cluster(), w.member("main", other), w.cluster().group("main")), "follow=1."+w.app("main", np)+".") {
		t.Fatal("the role file names the new primary for a restart")
	}
}

func TestPGFollowAndWritableArgumentsAreValidated(t *testing.T) {
	good := "host=1.pgc-db-main-m1.cluster.ziro port=5432 user=replicator application_name=m2"
	for _, c := range []struct {
		op, arg string
		ok      bool
	}{
		{opFollow, good, true},
		{opFollow, good + " sslmode=verify-ca sslrootcert=/var/lib/postgresql/data/ziro-tls/ca.crt", true},
		{opFollow, good + "' ; drop table x; --", false},
		{opFollow, "host=evil port=5432 user=postgres application_name=m2", false},
		{opFollow, "", false},
		{opWritable, "ANY 1 (m2, m3)", true},
		{opWritable, "", true},
		{opWritable, "ziro_fenced", false},
		{opReadonly, "x", false},
	} {
		if err := validPGCommand(c.op, c.arg); (err == nil) != c.ok {
			t.Errorf("%s %q: %v", c.op, c.arg, err)
		}
	}
	steps, _ := pgSteps(PGOrder{Container: "zc-pgc-db-main-m1-x", Op: opReadonly})
	if s := strings.Join(steps[0], " "); !strings.Contains(s, "synchronous_standby_names = 'ziro_fenced'") || !strings.Contains(s, "pg_terminate_backend") {
		t.Fatalf("readonly must fence commits and end sessions: %s", s)
	}
	steps, _ = pgSteps(PGOrder{Container: "zc-pgc-db-main-m1-x", Op: opWritable, Arg: "ANY 1 (m2, m3)"})
	if s := strings.Join(steps[0], " "); !strings.Contains(s, "synchronous_standby_names = 'ANY 1 (m2, m3)'") || !strings.Contains(s, "reset default_transaction_read_only") {
		t.Fatalf("writable restores the standby list: %s", s)
	}
}

func TestPGSwitchoverAbortRestoresTheStandbyList(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(6)
	w.stalled[w.app("main", "m2")] = true
	w.write(100)
	if err := pgRequestSwitchover(w.st, "db", "", "m2", w.now); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40 && w.cluster().group("main").Switch != nil; i++ {
		w.write(1)
		w.step(5 * time.Second)
	}
	var writable string
	for _, l := range w.log {
		if strings.HasPrefix(l, w.app("main", "m1")+" writable ") {
			writable = l
		}
	}
	if !strings.HasSuffix(writable, "writable ANY 1 (m2, m3)") {
		t.Fatalf("abort: %q (%v)", writable, w.log)
	}
}

func TestPGNewSpecRollsOneMemberAtATimePrimaryLast(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(10)
	revs := func() map[string]int {
		out := map[string]int{}
		for _, id := range []string{"m1", "m2", "m3"} {
			out[id] = w.st.app(w.app("main", id)).Revision
		}
		return out
	}
	before := revs()
	w.cluster().Resources = &Resources{Memory: "2Gi"} // new tuning: every member's spec changes
	var order []string
	seen := map[string]bool{}
	for i := 0; i < 60 && len(seen) < 3; i++ {
		w.step(5 * time.Second)
		changed := 0
		for id, r := range revs() {
			if r != before[id] && !seen[id] {
				seen[id] = true
				order = append(order, id)
				changed++
			}
		}
		if changed > 1 {
			t.Fatalf("two members took the new spec in one pass: %v", order)
		}
	}
	if len(order) != 3 || order[2] != "m1" {
		t.Fatalf("order %v (primary %s): the primary goes last (%s)", order, w.primaryOf("main"), w.events("main"))
	}
	if w.primaryOf("main") == "m1" {
		t.Fatalf("the primary was restarted in place instead of after a switchover: %s", w.events("main"))
	}
	if !strings.Contains(w.events("main"), "switching over to") {
		t.Fatalf("events: %s", w.events("main"))
	}
}

func TestPGClustersGetTLSWithTheirOwnCA(t *testing.T) {
	w := newPGWorld(t, 3)
	c := w.create(pgCreateOpts{Replicas: 1})
	sec, ca := w.st.Secrets[c.secretName()], w.st.Secrets[c.caSecretName()]
	if sec["PG_TLS_CERT"] == "" || sec["PG_TLS_KEY"] == "" || sec["PG_TLS_CA"] == "" || ca["CA_KEY"] == "" {
		t.Fatalf("missing TLS material: %v %v", len(sec), len(ca))
	}
	if _, ok := sec["CA_KEY"]; ok {
		t.Fatal("the CA key must not reach the members")
	}
	app := pgMemberApp(w.st, c, &c.Groups[0], &c.Groups[0].Members[0])
	if slices.Contains(app.Secrets, c.caSecretName()) {
		t.Fatal("members are given the CA secret")
	}
	decode := func(b64 string) *x509.Certificate {
		raw, _ := base64.StdEncoding.DecodeString(b64)
		blk, _ := pem.Decode(raw)
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	caCert, srv := decode(sec["PG_TLS_CA"]), decode(sec["PG_TLS_CERT"])
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	for _, name := range []string{"db-rw.cluster.ziro", "db-main-ro.cluster.ziro", "1.pgc-db-main-m2.cluster.ziro"} {
		if _, err := srv.Verify(x509.VerifyOptions{DNSName: name, Roots: pool}); err != nil && !strings.HasPrefix(name, "1.") {
			t.Errorf("%s: %v", name, err)
		}
	}
	other := w.create(pgCreateOpts{Name: "two", Replicas: 1})
	otherCA := decode(w.st.Secrets[other.secretName()]["PG_TLS_CA"])
	p2 := x509.NewCertPool()
	p2.AddCert(otherCA)
	if _, err := srv.Verify(x509.VerifyOptions{Roots: p2}); err == nil {
		t.Fatal("another cluster's CA accepts this cluster's certificate")
	}
	if u := pgConnString(w.st, c, false); !strings.HasSuffix(u, "?sslmode=require") {
		t.Fatalf("connection string: %s", u)
	}
	if err := pgDelete(w.st, "db", true); err != nil || w.st.Secrets[c.caSecretName()] != nil {
		t.Fatalf("purge keeps the CA: %v", err)
	}
}

func TestSCRAMVerifierMatchesPostgres(t *testing.T) {
	// computed independently (Python hashlib) and accepted by PostgreSQL 16 for the password "pencil"
	salt := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	want := "SCRAM-SHA-256$4096:AAECAwQFBgcICQoLDA0ODw==$zHCdol2044/ZyWzPLi7oxApCkamKw9Z+E4U/QApd/5Y=:dd5peBOitVnLNFu7VmwP+HiDaaw4OUCv396eVCWhYiE="
	if got, err := scramVerifier("pencil", salt); err != nil || got != want {
		t.Fatalf("%s %v", got, err)
	}
	if validPasswordArg("app:"+want) != nil || validPasswordArg("app:plaintext") == nil || validPasswordArg(`a"b:`+want) == nil {
		t.Fatal("password orders take a role and a verifier only")
	}
}

func TestPGPasswordRotationNeverSendsThePlaintext(t *testing.T) {
	w := newPGWorld(t, 3)
	c := w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	old := w.st.Secrets[c.secretName()]["POSTGRES_PASSWORD"]
	if err := pgRequestRotation(w.st, "db", "", w.now); err != nil {
		t.Fatal(err)
	}
	if err := pgRequestRotation(w.st, "db", "nobody", w.now); err == nil {
		t.Fatal("an unknown role is refused")
	}
	next := w.st.Secrets[c.caSecretName()]["NEXT_POSTGRES_PASSWORD"]
	if next == "" || next == old {
		t.Fatal("no new password staged")
	}
	before := w.st.app(w.app("main", "m2")).Revision
	w.settle(4)
	var order string
	for _, l := range w.log {
		if strings.Contains(l, " password ") {
			order = l
		}
		if strings.Contains(l, next) {
			t.Fatalf("an order carries the plaintext: %s", l)
		}
	}
	if !strings.Contains(order, " password app:SCRAM-SHA-256$4096:") {
		t.Fatalf("orders: %v", w.log)
	}
	if got := w.st.Secrets[c.secretName()]["POSTGRES_PASSWORD"]; got != next || c.Rotation != nil || c.SecretEpoch != 1 {
		t.Fatalf("secret %v, rotation %v, epoch %d", got == next, c.Rotation, c.SecretEpoch)
	}
	w.settle(20)
	if w.st.app(w.app("main", "m2")).Revision == before {
		t.Fatal("the members did not restart on the new secret")
	}
}

func TestPGDiskAlerts(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	g := &PGGroup{Members: []PGMember{{ID: "m1", Role: pgPrimary, Probe: PGProbe{At: now, OK: true, DiskPct: 93}}, {ID: "m2", Role: pgReplica, Probe: PGProbe{At: now, OK: true, DiskPct: 81}}}}
	pgDiskAlerts(g, now)
	pgDiskAlerts(g, now.Add(time.Minute))
	var high, medium int
	for _, e := range g.Events {
		switch e.Alert {
		case "high":
			high++
		case "medium":
			medium++
		}
	}
	if high != 1 || medium != 1 {
		t.Fatalf("alerts: %+v", g.Events)
	}
	if pct := diskUsedPct(t.TempDir()); pct <= 0 || pct > 100 {
		t.Fatalf("disk use of a real file system: %d", pct)
	}
}

func TestPGDangerousCommandsNeedConfirmation(t *testing.T) {
	old := pgFlags
	defer func() { pgFlags = old }()
	pgFlags.purge, pgFlags.yes = true, false
	if err := pgRmCmd.RunE(pgRmCmd, []string{"shop"}); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("rm --purge without --yes: %v", err)
	}
	pgFlags.port, pgFlags.allow = 5432, nil
	if err := pgExposeCmd.RunE(pgExposeCmd, []string{"shop"}); err == nil || !strings.Contains(err.Error(), "--allow") {
		t.Fatalf("expose without --allow: %v", err)
	}
	if f := pgCreateCmd.Flags().Lookup("replicas"); f == nil || f.DefValue != "2" {
		t.Fatal("clusters are created with two replicas (synchronous) by default")
	}
}
