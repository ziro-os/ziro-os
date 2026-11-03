package cmd

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ziro-os/ziro-os/sdk/schema"
)

func parsePGFile(t *testing.T, y string) PostgresConfig {
	t.Helper()
	if kind, _ := schema.Kind([]byte(y)); kind != "postgres" {
		t.Fatalf("kind %q", kind)
	}
	cfg, err := schema.ParsePostgresConfig([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func planLines(p *pgPlan) []string {
	var out []string
	for _, c := range p.Changes {
		out = append(out, c.Action+" "+c.Section+" "+c.Item)
	}
	return out
}

func hasLine(lines []string, prefix string) bool {
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return false
}

func TestPGFileSchema(t *testing.T) {
	ok := `
postgres:
  version: 1
  name: shop
  postgres: "17"
  replicas: 2
  resources: {memory: 4Gi, cpus: 2}
  params: {work_mem: 64MB}
  pooler: {enabled: true, mode: transaction, size: 40}
  backup: {endpoint: s3.eu-west-1.amazonaws.com, bucket: acme-db, schedule: {incr: "15 * * * *"}}
  maintenance: {window: "0 2 * * 0", duration: 2h}
`
	parsePGFile(t, ok)
	for name, bad := range map[string]string{
		"version":       "postgres: {version: 2, name: shop}",
		"name":          "postgres: {version: 1, name: Shop-1}",
		"major":         "postgres: {version: 1, name: shop, postgres: '15'}",
		"unknown field": "postgres: {version: 1, name: shop, replica: 2}",
		"image digest":  "postgres: {version: 1, name: shop, image: 'postgres:17'}",
		"shards":        "postgres: {version: 1, name: shop, shards: 2}",
		"sync":          "postgres: {version: 1, name: shop, sync: async}",
		"database":      "postgres: {version: 1, name: shop, database: 'app; drop'}",
		"pooler mode":   "postgres: {version: 1, name: shop, pooler: {enabled: true, mode: statement}}",
		"backup bucket": "postgres: {version: 1, name: shop, backup: {endpoint: s3.amazonaws.com}}",
		"backup cron":   "postgres: {version: 1, name: shop, backup: {endpoint: e, bucket: b, schedule: {full: daily}}}",
		"window":        "postgres: {version: 1, name: shop, maintenance: {window: sundays, duration: 2h}}",
		"duration":      "postgres: {version: 1, name: shop, maintenance: {window: '0 2 * * 0', duration: 5m}}",
		"param name":    "postgres: {version: 1, name: shop, params: {'work_mem = 1; x': '1'}}",
	} {
		if _, err := schema.ParsePostgresConfig([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Turning things off needs no other field.
	parsePGFile(t, "postgres: {version: 1, name: shop, backup: {enabled: false}, maintenance: {}, paused: false}")
}

func TestPGApplyCreatesAClusterAndIsIdempotent(t *testing.T) {
	w := newPGWorld(t, 3)
	cfg := parsePGFile(t, `
postgres:
  version: 1
  name: db
  replicas: 2
  resources: {memory: 2Gi}
  params: {work_mem: 32MB, max_connections: "300"}
  pooler: {enabled: true, size: 40}
  maintenance: {window: "0 2 * * 0", duration: 3h}
`)
	plan, err := pgPlanFile(w.st, cfg, pgApplyKeys{}, w.now)
	if err != nil {
		t.Fatal(err)
	}
	if w.st.PG["db"] != nil {
		t.Fatal("planning created the cluster")
	}
	lines := planLines(plan)
	for _, want := range []string{"create cluster db", "unchanged replicas 2", "unchanged resources memory 2Gi", "create param max_connections=300",
		"create param work_mem=32MB", "update pooler transaction, 40", "create maintenance 0 2 * * 0 for 3h"} {
		if !hasLine(lines, want) {
			t.Errorf("plan lacks %q:\n%s", want, strings.Join(lines, "\n"))
		}
	}
	if len(plan.refused()) > 0 {
		t.Fatalf("refused: %v", plan.refused())
	}
	if applied := pgApplySpec(w.st, cfg, pgApplyKeys{}, w.now); len(applied.refused()) > 0 {
		t.Fatalf("apply refused: %v", applied.refused())
	}
	c := w.cluster()
	if c == nil || c.Params["work_mem"] != "32MB" || c.Pooler.Size != 40 || c.Maintenance.Duration != "3h" || c.Resources.Memory != "2Gi" {
		t.Fatalf("applied: %+v", c)
	}
	// The same file again, and pg get's own file, change nothing.
	again := pgApplySpec(w.st, cfg, pgApplyKeys{}, w.now)
	if again.changed() {
		t.Fatalf("second apply changed: %v", planLines(again))
	}
	w.settle(8)
	y, err := schema.ToYAML(pgSpecOf(w.cluster()))
	if err != nil {
		t.Fatal(err)
	}
	exported := parsePGFile(t, string(y))
	if p := pgApplySpec(w.st, exported, pgApplyKeys{}, w.now); p.changed() {
		t.Fatalf("pg get's file is not a no-op: %v\n%s", planLines(p), y)
	}
	for _, secret := range []string{w.st.Secrets[c.secretName()]["POSTGRES_PASSWORD"], "PG_TLS_KEY"} {
		if strings.Contains(string(y), secret) {
			t.Fatal("pg get prints a secret")
		}
	}
}

func TestPGApplyChangesAndRefusals(t *testing.T) {
	w := newPGWorld(t, 4)
	w.create(pgCreateOpts{Replicas: 2})
	if err := pgSetParams(w.st, "db", map[string]string{"work_mem": "16MB", "max_connections": "400"}); err != nil {
		t.Fatal(err)
	}
	w.settle(8)
	// A field left out keeps its value; params is the whole list.
	cfg := parsePGFile(t, `
postgres:
  version: 1
  name: db
  replicas: 3
  params: {max_connections: "400", statement_timeout: 30s}
  allow_from: [web, api]
  paused: true
`)
	plan := pgApplySpec(w.st, cfg, pgApplyKeys{}, w.now)
	lines := planLines(plan)
	for _, want := range []string{"update replicas 3", "unchanged param max_connections=400", "create param statement_timeout=30s",
		"remove param work_mem", "update allow_from api, web", "update paused true"} {
		if !hasLine(lines, want) {
			t.Errorf("plan lacks %q:\n%s", want, strings.Join(lines, "\n"))
		}
	}
	c := w.cluster()
	if c.Replicas != 3 || c.Params["work_mem"] != "" || c.Params["statement_timeout"] != "30s" || !c.Paused || c.Pooler == nil || !c.Pooler.Enabled {
		t.Fatalf("cluster: replicas %d params %v paused %v pooler %+v", c.Replicas, c.Params, c.Paused, c.Pooler)
	}
	// What cannot change is refused, and a plan on a copy leaves the cluster alone.
	for name, y := range map[string]string{
		"major":     "postgres: {version: 1, name: db, postgres: '18'}",
		"sync":      "postgres: {version: 1, name: db, sync: 'off'}",
		"database":  "postgres: {version: 1, name: db, database: other}",
		"sharded":   "postgres: {version: 1, name: db, shards: 2, citus_image: 'citus:13@sha256:" + strings.Repeat("c", 64) + "'}",
		"grow-only": "postgres: {version: 1, name: db, params: {statement_timeout: 30s}}", // drops max_connections
		"image":     "postgres: {version: 1, name: db, image: 'docker.io/library/postgres:18@sha256:" + strings.Repeat("a", 64) + "'}",
		"backup":    "postgres: {version: 1, name: db, backup: {endpoint: s3.amazonaws.com, bucket: acme-db}}", // no keys
	} {
		before := fmt.Sprintf("%+v", *w.cluster())
		p, err := pgPlanFile(w.st, parsePGFile(t, y), pgApplyKeys{}, w.now)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.refused()) == 0 {
			t.Errorf("%s: not refused: %v", name, planLines(p))
		}
		if after := fmt.Sprintf("%+v", *w.cluster()); after != before {
			t.Errorf("%s: planning changed the cluster", name)
		}
	}
}

func TestPGApplyTurnsBackupsOnAndOff(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2, Version: "17"})
	cfg := parsePGFile(t, `
postgres:
  version: 1
  name: db
  image: "`+testBackupImage+`"
  backup: {endpoint: s3.eu-west-1.amazonaws.com, bucket: acme-db, region: eu-west-1, retention: 8, schedule: {incr: "15 * * * *"}}
`)
	plan := pgApplySpec(w.st, cfg, pgApplyKeys{KeyID: "AKIAEXAMPLE", Secret: "secret"}, w.now)
	if len(plan.refused()) > 0 {
		t.Fatalf("refused: %v", plan.refused())
	}
	c := w.cluster()
	if c.Backup == nil || c.Backup.Retention != 8 || c.Backup.Incr != "15 * * * *" || c.Backup.Full != "0 1 * * 0" || c.Image != testBackupImage {
		t.Fatalf("backup: %+v image %s", c.Backup, c.Image)
	}
	if again := pgApplySpec(w.st, cfg, pgApplyKeys{}, w.now); again.changed() {
		t.Fatalf("not idempotent: %v", planLines(again))
	}
	if spec := pgSpecOf(c); spec.Postgres.Backup == nil || spec.Postgres.Backup.Schedule.Incr != "15 * * * *" {
		t.Fatal("pg get loses the schedule")
	}
	off := pgApplySpec(w.st, parsePGFile(t, "postgres: {version: 1, name: db, backup: {enabled: false}}"), pgApplyKeys{}, w.now)
	if !hasLine(planLines(off), "remove backup") || c.Backup != nil {
		t.Fatalf("backups stay on: %v", planLines(off))
	}
}

func TestPGMaintenanceWindow(t *testing.T) {
	c := &PGCluster{Name: "db"}
	at := func(s string) time.Time {
		v, _ := time.Parse(time.RFC3339, s)
		return v
	}
	if !pgWindowOpen(c, at("2026-10-21T12:00:00Z")) {
		t.Fatal("no window: always open")
	}
	c.Maintenance = &PGMaintenance{Window: "0 2 * * 0", Duration: "2h"} // Sundays 02:00-04:00
	for when, open := range map[string]bool{
		"2026-10-25T01:59:00Z": false, "2026-10-25T02:00:00Z": true, "2026-10-25T03:59:00Z": true,
		"2026-10-25T04:00:00Z": false, "2026-10-21T12:00:00Z": false,
	} {
		if pgWindowOpen(c, at(when)) != open {
			t.Errorf("%s: open should be %v", when, open)
		}
	}
	if n := pgNextWindow(c, at("2026-10-21T12:00:00Z")); !n.Equal(at("2026-10-25T02:00:00Z")) {
		t.Fatalf("next window %s", n)
	}
	if l := pgWindowLabel(c, at("2026-10-21T12:00:00Z")); l != "0 2 * * 0 for 2h (next 2026-10-25 02:00 UTC)" {
		t.Fatalf("label %q", l)
	}
	for _, bad := range []PGMaintenance{{Window: "sundays", Duration: "2h"}, {Window: "0 2 * * 0", Duration: "10m"}, {Window: "0 2 * * 0", Duration: "48h"}} {
		if bad.validate() == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func TestPGRestartsWaitForTheMaintenanceWindow(t *testing.T) {
	w := newPGWorld(t, 3) // Wednesday 2026-10-21 12:00 UTC
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	revs := func() []int {
		var r []int
		for _, id := range []string{"m1", "m2", "m3"} {
			r = append(r, w.st.app(w.app("main", id)).Revision)
		}
		return r
	}
	if err := pgSetMaintenance(w.st, "db", "0 2 * * 0", "2h"); err != nil {
		t.Fatal(err)
	}
	before := revs()
	if err := pgSetParams(w.st, "db", map[string]string{"max_connections": "400"}); err != nil {
		t.Fatal(err)
	}
	w.settle(30)
	if !slices.Equal(revs(), before) {
		t.Fatalf("members restarted outside the window: %v -> %v", before, revs())
	}
	g := w.cluster().group("main")
	if len(g.Waiting) != 3 || !strings.Contains(w.events("main"), "restart in the maintenance window") {
		t.Fatalf("waiting %v; events %s", g.Waiting, w.events("main"))
	}
	if v := pgViewOf(w.st, w.cluster(), w.now); len(v.Groups[0].Waiting) != 3 || !strings.Contains(v.Window, "next 2026-10-25 02:00") {
		t.Fatalf("view: %+v", v)
	}
	if o := pgOverviewOf(w.st, w.cluster(), w.now); o.Health != "degraded" || !strings.Contains(strings.Join(o.Attention, ";"), "wait for the maintenance window") {
		t.Fatalf("overview: %+v", o)
	}
	// Opening it by hand rolls them, one at a time.
	if err := pgOpenWindow(w.st, "db", time.Hour, w.now); err != nil {
		t.Fatal(err)
	}
	w.settle(40)
	after := revs()
	for i := range after {
		if after[i] == before[i] {
			t.Fatalf("member %d did not restart in the window: %v -> %v", i+1, before, after)
		}
	}
	if len(w.cluster().group("main").Waiting) != 0 {
		t.Fatal("still waiting")
	}
	if err := pgOpenWindow(w.st, "db", 0, w.now); err != nil || !w.cluster().WindowUntil.IsZero() {
		t.Fatal("close by hand")
	}
}

func TestPGPasswordRotationDoesNotWaitForTheWindow(t *testing.T) {
	w := newPGWorld(t, 3)
	c := w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	if err := pgSetMaintenance(w.st, "db", "0 2 * * 0", "2h"); err != nil {
		t.Fatal(err)
	}
	before := w.st.app(w.app("main", "m2")).Revision
	if err := pgRequestRotation(w.st, "db", "replicator", w.now); err != nil {
		t.Fatal(err)
	}
	w.settle(40)
	if c.SecretEpoch != 1 || w.st.app(w.app("main", "m2")).Revision == before {
		t.Fatalf("the members did not restart on the new password: epoch %d", c.SecretEpoch)
	}
}

func TestPGEventHistory(t *testing.T) {
	w := newPGWorld(t, 3)
	c := w.create(pgCreateOpts{Replicas: 2})
	g := &c.Groups[0]
	start := w.now
	for i := 0; i < 250; i++ {
		g.note(start.Add(time.Duration(i)*time.Second), "event %d", i)
	}
	g.alert(start.Add(300*time.Second), "high", "something broke")
	if len(g.Events) != pgEventsKept {
		t.Fatalf("kept %d events", len(g.Events))
	}
	all := pgEventsOf(c, "", time.Time{})
	if len(all) != pgEventsKept || all[0].Message != "event 51" || all[len(all)-1].Severity != "high" {
		t.Fatalf("events: first %+v last %+v", all[0], all[len(all)-1])
	}
	recent := pgEventsOf(c, "main", start.Add(245*time.Second))
	if len(recent) != 5 || recent[0].Message != "event 246" {
		t.Fatalf("since: %+v", recent)
	}
	if len(pgEventsOf(c, "w1", time.Time{})) != 0 {
		t.Fatal("another group's events")
	}
	if v := pgViewOf(w.st, c, w.now); len(v.Groups[0].Events) != pgEventsStatus {
		t.Fatalf("pg status shows %d events", len(v.Groups[0].Events))
	}
	if !strings.Contains(pgEventLine(all[len(all)-1]), "main  [high] something broke") {
		t.Fatalf("line %q", pgEventLine(all[len(all)-1]))
	}
}

func TestPGOverview(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.create(pgCreateOpts{Name: "logs", Replicas: 1})
	w.settle(8)
	rows := pgOverview(w.st, w.now)
	if len(rows) != 2 {
		t.Fatalf("%d rows", len(rows))
	}
	for _, r := range rows {
		if r.Health != "healthy" || r.Ready != r.Members || r.Primary == "" || len(r.Attention) != 0 {
			t.Fatalf("%+v", r)
		}
	}
	// The primary of db stops answering: db is down and comes first.
	w.down[w.member("main", "m1").Node] = true
	w.step(5 * time.Second)
	w.st.PG["logs"].Paused = true
	rows = pgOverview(w.st, w.now.Add(pgGrace+5*time.Second)) // past the failover grace, before a pass promotes
	if rows[0].Name != "db" || rows[0].Health != "down" || rows[1].Health != "paused" {
		t.Fatalf("order and health: %s=%s %s=%s", rows[0].Name, rows[0].Health, rows[1].Name, rows[1].Health)
	}
	if len(rows[0].Attention) == 0 {
		t.Fatal("no reason given for a cluster that is down")
	}
	// Backups on with nothing finished, and a full disk, need attention.
	c := w.st.PG["logs"]
	c.Paused = false
	if err := pgBackupEnable(w.st, "logs", testRepo(), "AKIAEXAMPLE", "secret", testBackupImage); err != nil {
		t.Fatal(err)
	}
	c.Groups[0].Members[0].Probe.DiskPct = 91
	o := pgOverviewOf(w.st, c, w.now)
	att := strings.Join(o.Attention, "; ")
	if !o.Backups || !strings.Contains(att, "no backup has finished yet") || !strings.Contains(att, "91% full") || o.DiskPct != 91 {
		t.Fatalf("%+v", o)
	}
}

func TestPGCronNext(t *testing.T) {
	s, _ := pgParseCron("30 * * * *")
	at, _ := time.Parse(time.RFC3339, "2026-11-03T04:30:00Z")
	if n := s.next(at); n.Format(time.RFC3339) != "2026-11-03T05:30:00Z" {
		t.Fatalf("next %s", n)
	}
	s, _ = pgParseCron("0 2 1 1 *")
	if n := s.next(at); n.Format(time.RFC3339) != "2027-01-01T02:00:00Z" {
		t.Fatalf("next %s", n)
	}
}
