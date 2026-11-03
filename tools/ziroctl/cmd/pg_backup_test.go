package cmd

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const testBackupImage = "ghcr.io/ziro-os/postgres:17-pgbackrest@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func testRepo() PGBackup {
	return PGBackup{Endpoint: "s3.eu-west-1.amazonaws.com", Bucket: "acme-db", Region: "eu-west-1", Path: "/ziro"}
}

func TestPGCronSchedules(t *testing.T) {
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, c := range []struct {
		spec, now, prev string
	}{
		{"30 * * * *", "2026-11-03T04:57:47Z", "2026-11-03T04:30:00Z"},
		{"30 * * * *", "2026-11-03T04:30:00Z", "2026-11-03T04:30:00Z"},
		{"0 1 * * 0", "2026-11-03T04:57:00Z", "2026-11-01T01:00:00Z"}, // the Sunday before (Nov 3 2026 is a Tuesday)
		{"0 1 * * 7", "2026-11-03T04:57:00Z", "2026-11-01T01:00:00Z"}, // 7 is Sunday too
		{"0 1 * * 1-6", "2026-11-03T00:30:00Z", "2026-11-02T01:00:00Z"},
		{"*/15 2 * * *", "2026-11-03T02:44:00Z", "2026-11-03T02:30:00Z"},
		{"0 3 1,15 * *", "2026-11-14T00:00:00Z", "2026-11-01T03:00:00Z"},
		{"0 0 1 1 *", "2026-11-03T00:00:00Z", "2026-01-01T00:00:00Z"},
	} {
		s, err := pgParseCron(c.spec)
		if err != nil {
			t.Fatalf("%s: %v", c.spec, err)
		}
		if got := s.prev(at(c.now)); !got.Equal(at(c.prev)) {
			t.Errorf("%q at %s: prev %s, want %s", c.spec, c.now, got.Format(time.RFC3339), c.prev)
		}
	}
	// Both day fields restricted: either matches, as in cron.
	s, _ := pgParseCron("0 0 13 * 5")
	if !s.matches(at("2026-11-13T00:00:00Z")) || !s.matches(at("2026-11-06T00:00:00Z")) || s.matches(at("2026-11-07T00:00:00Z")) {
		t.Fatal("day of month or day of week")
	}
	for spec, gap := range map[string]time.Duration{"30 * * * *": time.Hour, "0 1 * * 0": 7 * 24 * time.Hour, "0 1 * * 1-6": 48 * time.Hour} {
		s, _ := pgParseCron(spec)
		if got := s.gap(at("2026-11-03T04:57:00Z")); got != gap {
			t.Errorf("%q: gap %s, want %s", spec, got, gap)
		}
	}
	for _, bad := range []string{"", "* * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "* * * * 8", "*/0 * * * *", "a * * * *", "5-1 * * * *", "* * * * * *"} {
		if _, err := pgParseCron(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestPGBackupEnableChecksAndKeepsKeysInTheSecret(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2, Version: "17"})
	repo := testRepo()
	if err := pgBackupEnable(w.st, "db", repo, "", "", testBackupImage); err == nil || !strings.Contains(err.Error(), "access key") {
		t.Fatalf("keys are required: %v", err)
	}
	if err := pgBackupEnable(w.st, "db", repo, "AKIAEXAMPLE", "secret/key+x=", "ghcr.io/ziro-os/postgres:17"); err == nil {
		t.Fatal("an image not pinned by digest is refused")
	}
	if pgBackupImages["17"] == "" {
		if err := pgBackupEnable(w.st, "db", repo, "AKIAEXAMPLE", "secret/key+x=", ""); err == nil || !strings.Contains(err.Error(), "--image") {
			t.Fatalf("without published images --image is needed: %v", err)
		}
	}
	for _, bad := range []PGBackup{
		{Endpoint: "https://s3.amazonaws.com", Bucket: "b-1", Region: "us-east-1", Path: "/z"},
		{Endpoint: "s3.amazonaws.com", Bucket: "B", Region: "us-east-1", Path: "/z"},
		{Endpoint: "s3.amazonaws.com", Bucket: "bucket", Region: "us east", Path: "/z"},
		{Endpoint: "s3.amazonaws.com", Bucket: "bucket", Region: "us-east-1", Path: "/z/../x y"},
		{Endpoint: "s3.amazonaws.com", Bucket: "bucket", Region: "us-east-1", Path: "/z", Full: "every day"},
		{Endpoint: "s3.amazonaws.com", Bucket: "bucket", Region: "us-east-1", Path: "/z", URIStyle: "virtual"},
		{Endpoint: "s3.amazonaws.com\nrepo1-path=/x", Bucket: "bucket", Region: "us-east-1", Path: "/z"},
	} {
		if err := pgBackupEnable(w.st, "db", bad, "AKIAEXAMPLE", "secret", testBackupImage); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	if err := pgBackupEnable(w.st, "db", repo, "AKIAEXAMPLE", "secret", "ghcr.io/x@sha256:1 \n"); err == nil {
		t.Fatal("an image with spaces is refused")
	}
	if err := pgBackupEnable(w.st, "db", repo, "AKIAEXAMPLE", "secret/key+x=", testBackupImage); err != nil {
		t.Fatal(err)
	}
	c := w.cluster()
	if c.Image != testBackupImage || c.Backup.Retention != 4 || c.Backup.Full != "0 1 * * 0" || c.Backup.Incr != "30 * * * *" {
		t.Fatalf("defaults: %+v image %s", c.Backup, c.Image)
	}
	sec := w.st.Secrets[c.backupSecret()]
	pass := sec["PGBACKREST_REPO1_CIPHER_PASS"]
	if len(pass) != 48 || sec["PGBACKREST_REPO1_S3_KEY"] != "AKIAEXAMPLE" || sec["PGBACKREST_REPO1_S3_KEY_SECRET"] != "secret/key+x=" {
		t.Fatalf("secret: %v", sec)
	}
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), "secret/key+x=") || strings.Contains(string(b), pass) {
		t.Fatal("the keys are in the cluster spec")
	}
	// Changing the configuration keeps the passphrase (a new one would make the old backups unreadable).
	repo.Retention = 8
	if err := pgBackupEnable(w.st, "db", repo, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if w.st.Secrets[c.backupSecret()]["PGBACKREST_REPO1_CIPHER_PASS"] != pass || c.Backup.Retention != 8 {
		t.Fatal("the passphrase changed")
	}
	// The members get the configuration, the keys and the stanza.
	w.step(5 * time.Second)
	a := w.st.app(w.app("main", "m1"))
	conf := a.ConfigFiles["pgbackrest.conf"]
	for _, want := range []string{"repo1-type=s3\n", "repo1-s3-endpoint=s3.eu-west-1.amazonaws.com\n", "repo1-s3-bucket=acme-db\n",
		"repo1-path=/ziro/db\n", "repo1-cipher-type=aes-256-cbc\n", "repo1-retention-full=8\n", "compress-type=zst\n", "archive-async=y\n",
		"\n[main]\npg1-path="} {
		if !strings.Contains(conf, want) {
			t.Errorf("pgbackrest.conf lacks %q:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "secret") || strings.Contains(conf, pass) {
		t.Fatal("keys in the config file")
	}
	if a.Image != testBackupImage || a.Env["ZIRO_PG_STANZA"] != "main" || a.Env["PGBACKREST_CONFIG"] == "" {
		t.Fatalf("member app: image %s env %v", a.Image, a.Env)
	}
	hasSecret := false
	for _, s := range a.Secrets {
		hasSecret = hasSecret || s == c.backupSecret()
	}
	if !hasSecret {
		t.Fatal("the member does not get the backup secret")
	}
	if err := pgBackupDisable(w.st, "db"); err != nil || c.Backup != nil {
		t.Fatal("disable")
	}
	w.advance(3 * time.Minute) // the members restart one at a time
	for _, id := range []string{"m1", "m2", "m3"} {
		if _, ok := w.st.app(w.app("main", id)).ConfigFiles["pgbackrest.conf"]; ok {
			t.Fatalf("%s keeps the config after disable", id)
		}
	}
}

// backupWorld is a three-member cluster with backups on, run until it is healthy.
func backupWorld(t *testing.T) *pgWorld {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2, Version: "17"})
	w.settle(8)
	if err := pgBackupEnable(w.st, "db", testRepo(), "AKIAEXAMPLE", "secret", testBackupImage); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *pgWorld) ops(op string) []string {
	var out []string
	for _, l := range w.log {
		if f := strings.Fields(l); len(f) >= 2 && f[1] == op {
			out = append(out, l)
		}
	}
	return out
}

func TestPGBackupScheduleRunsOnThePrimary(t *testing.T) {
	w := backupWorld(t)
	w.settle(4)
	stanza := w.ops(opStanza)
	if len(stanza) != 1 || !strings.HasPrefix(stanza[0], w.app("main", w.primaryOf("main"))+" stanza main") {
		t.Fatalf("stanza orders: %v", stanza)
	}
	backups := w.ops(opBackup)
	if len(backups) != 1 || !strings.HasSuffix(backups[0], " backup full") || !strings.HasPrefix(backups[0], w.app("main", w.primaryOf("main"))) {
		t.Fatalf("the first backup is a full one on the primary: %v", backups)
	}
	// Nothing more until the next firing: 12:30 (incremental, hourly), then 01:00 on a weekday (differential).
	w.settle(20)
	if n := len(w.ops(opBackup)); n != 1 {
		t.Fatalf("%d backups before the next firing: %v", n, w.ops(opBackup))
	}
	w.advance(time.Date(2026, 10, 21, 12, 31, 0, 0, time.UTC).Sub(w.now))
	if b := w.ops(opBackup); len(b) != 2 || !strings.HasSuffix(b[1], " backup incr") {
		t.Fatalf("an incremental at half past: %v", b)
	}
	// The schedule over a week (without the simulation: what it would ask for at each minute).
	c := w.cluster()
	gb := &PGGroupBackup{Started: map[string]time.Time{}}
	var types []string
	for at := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC); at.Before(time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)); at = at.Add(time.Minute) {
		if typ := pgBackupDue(c.Backup, gb, at); typ != "" {
			pgBackupSettle(&PGGroup{Backup: gb}, &PGCommand{Op: opBackup, Arg: typ, OK: true}, at)
			types = append(types, at.Format("Mon 15:04")+" "+typ)
		}
	}
	if len(types) != 1+7*24+7 || types[0] != "Wed 12:00 full" || types[1] != "Wed 12:30 incr" {
		t.Fatalf("%d backups: %v", len(types), types[:3])
	}
	var notIncr []string
	for _, x := range types[1:] {
		if !strings.HasSuffix(x, " incr") {
			notIncr = append(notIncr, x)
		}
	}
	if got := strings.Join(notIncr, ", "); got != "Thu 01:00 diff, Fri 01:00 diff, Sat 01:00 diff, Sun 01:00 full, Mon 01:00 diff, Tue 01:00 diff, Wed 01:00 diff" {
		t.Fatalf("differentials and fulls: %s", got)
	}
	// A backup asked for now runs at once, whatever the schedule.
	if err := pgBackupNow(w.st, "db", "", "full"); err != nil {
		t.Fatal(err)
	}
	w.step(5 * time.Second)
	w.step(5 * time.Second)
	if b := w.ops(opBackup); !strings.HasSuffix(b[len(b)-1], " backup full") || w.cluster().group("main").Backup.Now != "" {
		t.Fatalf("backup now: %v", b[len(b)-3:])
	}
	if err := pgBackupNow(w.st, "db", "", "everything"); err == nil {
		t.Fatal("a bad type is refused")
	}
}

func TestPGBackupWaitsForARunningOne(t *testing.T) {
	w := backupWorld(t)
	w.settle(4)
	g := w.cluster().group("main")
	g.Backup.Info = &PGBackupInfo{At: w.now, Running: true}
	for w.now.Before(time.Date(2026, 10, 21, 12, 40, 0, 0, time.UTC)) {
		w.step(5 * time.Second)
		g.Backup.Info = &PGBackupInfo{At: w.now, Running: true}
	}
	if n := len(w.ops(opBackup)); n != 1 {
		t.Fatalf("a backup started while one runs: %v", w.ops(opBackup))
	}
	g.Backup.Info.Running = false
	w.advance(10 * time.Second)
	if n := len(w.ops(opBackup)); n != 2 {
		t.Fatalf("the due incremental starts once the full one is done: %v", w.ops(opBackup))
	}
}

func TestPGBackupAlertsOnArchiveFailuresAndLateBackups(t *testing.T) {
	w := backupWorld(t)
	c := w.cluster()
	g := c.group("main")
	p := g.primary()
	// Before the stanza exists every archive attempt fails: no alert for those.
	p.Probe.ArchiveFailed = 12
	pgBackupPass(c, g, w.now)
	if g.Backup.Failed != 12 || strings.Contains(w.events("main"), "archiving") {
		t.Fatalf("failures before the stanza: %+v %s", g.Backup, w.events("main"))
	}
	g.Backup.Stanza = true
	p.Probe.ArchiveFailed = 15
	p.Cmd = nil
	pgBackupPass(c, g, w.now)
	if !strings.Contains(w.events("main"), "WAL archiving to the backup repository fails (3 failures)") {
		t.Fatalf("no alert: %s", w.events("main"))
	}
	// A restarted server starts counting again.
	p.Probe.ArchiveFailed = 0
	pgBackupPass(c, g, w.now)
	if g.Backup.Failed != 0 {
		t.Fatal("the counter is not reset")
	}
	// No backup finished for longer than the schedule allows (hourly: two hours and a margin).
	g.Backup.Started = map[string]time.Time{"full": w.now.Add(-30 * time.Hour), "diff": w.now.Add(-30 * time.Hour), "incr": w.now.Add(-30 * time.Hour)}
	g.Backup.Info = &PGBackupInfo{At: w.now, Backups: []PGBackupSummary{{Label: "20261020-060000F", Type: "full", Stop: w.now.Add(-30 * time.Hour)}},
		LastLog: "ERROR: [039]: HTTP request failed with 403 (Forbidden)"}
	pgBackupLate(c, g, w.now)
	if ev := w.events("main"); !strings.Contains(ev, "no backup finished since 2026-10-20T06:00") || !strings.Contains(ev, ": ERROR: [039]") {
		t.Fatalf("late backup: %s", ev)
	}
	g.Backup.Info.Backups = append(g.Backup.Info.Backups, PGBackupSummary{Label: "20261020-060000F_20261021-113000I", Type: "incr", Stop: w.now.Add(-20 * time.Minute)})
	before := len(g.Events)
	pgBackupLate(c, g, w.now.Add(7*time.Hour))
	if len(g.Events) != before+1 {
		t.Fatal("an incremental 7 hours old is late too")
	}
	pgBackupLate(c, g, w.now.Add(14*time.Hour))
	pgBackupLate(c, g, w.now.Add(14*time.Hour+time.Minute))
	if len(g.Events) != before+2 {
		t.Fatalf("the alert repeats at most every 6 hours: %d", len(g.Events)-before)
	}
}

func TestParseBackrestInfo(t *testing.T) {
	// pgbackrest info --output=json, abridged from pgBackRest 2.56 (one full, one diff, one incr; a backup running).
	out := `[{"archive":[{"database":{"id":1,"repo-key":1},"id":"17-1","max":"000000010000000000000009","min":"000000010000000000000003"}],
"backup":[
 {"archive":{"start":"000000010000000000000003","stop":"000000010000000000000003"},"backrest":{"format":5,"version":"2.56.0"},
  "database":{"id":1,"repo-key":1},"error":false,"info":{"delta":31477376,"repository":{"delta":4020563,"size":4020563},"size":31477376},
  "label":"20261101-010002F","prior":null,"reference":null,"timestamp":{"start":1761958802,"stop":1761958810},"type":"full"},
 {"info":{"delta":8192,"repository":{"delta":420,"size":420},"size":31485568},"label":"20261101-010002F_20261102-010001D",
  "timestamp":{"start":1762045201,"stop":1762045204},"type":"diff"},
 {"info":{"delta":8192,"repository":{"delta":400,"size":400},"size":31485568},"label":"20261101-010002F_20261102-023001I",
  "timestamp":{"start":1762050601,"stop":1762050603},"type":"incr"},
 {"info":{"size":1},"label":"../../etc/passwd","timestamp":{"start":1,"stop":2},"type":"full"}
],
"cipher":"aes-256-cbc","db":[{"id":1,"repo-key":1,"system-id":7567290862513567321,"version":"17"}],"name":"main",
"repo":[{"cipher":"aes-256-cbc","key":1,"status":{"code":0,"message":"ok"}}],
"status":{"code":0,"lock":{"backup":{"held":true}},"message":"ok"}}]`
	info, err := parseBackrestInfo(out)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Running || info.Status != "ok" || len(info.Backups) != 3 {
		t.Fatalf("%+v", info)
	}
	f := info.Backups[0]
	if f.Label != "20261101-010002F" || f.Type != "full" || f.Size != 31477376 || f.Repo != 4020563 || f.Stop.Sub(f.Start) != 8*time.Second {
		t.Fatalf("full: %+v", f)
	}
	if info.Backups[2].Type != "incr" || info.Backups[2].Repo != 400 {
		t.Fatalf("incr: %+v", info.Backups[2])
	}
	empty, err := parseBackrestInfo(`[{"archive":[],"backup":[],"name":"main","status":{"code":2,"lock":{"backup":{"held":false}},"message":"no valid backups"}}]`)
	if err != nil || empty.Status != "no valid backups" || len(empty.Backups) != 0 {
		t.Fatalf("%+v %v", empty, err)
	}
	for _, bad := range []string{"", "[]", "WARN: something", `[{"name":"a"},{"name":"b"}]`} {
		if _, err := parseBackrestInfo(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestPGRecoverableWindowAndViews(t *testing.T) {
	w := backupWorld(t)
	w.settle(4)
	c := w.cluster()
	g := c.group("main")
	if _, _, ok := pgRecoverable(g); ok {
		t.Fatal("no window without a backup")
	}
	g.Backup.Info = &PGBackupInfo{At: w.now, Status: "ok", Backups: []PGBackupSummary{
		{Label: "20261021-120000F", Type: "full", Start: w.now.Add(-time.Hour), Stop: w.now.Add(-50 * time.Minute), Size: 3 << 30, Repo: 400 << 20}}}
	g.primary().Probe.ArchivedAgo = 40
	from, to, ok := pgRecoverable(g)
	if !ok || !from.Equal(w.now.Add(-50*time.Minute)) || to.After(w.now) || w.now.Sub(to) > 2*time.Minute {
		t.Fatalf("window %s .. %s", from, to)
	}
	v := pgBackupViews(c)
	if len(v) != 1 || v[0].Repository != "s3://acme-db/ziro/db (stanza main)" || v[0].RecoverableFrom == "" || len(v[0].Backups) != 1 {
		t.Fatalf("%+v", v)
	}
	if humanSize(3<<30) != "3.0 GiB" || humanSize(400<<20) != "400.0 MiB" || humanSize(2048) != "2 KiB" {
		t.Fatal("sizes")
	}
}

func TestPGRestoreMakesANewClusterFromTheRepository(t *testing.T) {
	w := backupWorld(t)
	src := w.cluster()
	if _, err := pgRestore(w.st, pgRestoreOpts{Name: "db2", From: "db", Target: "yesterday"}, w.now); err == nil {
		t.Fatal("a bad target is refused")
	}
	c, err := pgRestore(w.st, pgRestoreOpts{Name: "db2", From: "db", Target: "2026-10-21T11:00:00Z", Replicas: 1}, w.now)
	if err != nil {
		t.Fatal(err)
	}
	if c.Backup == nil || c.Backup.Restore == nil || c.Backup.Restore.Path != "/ziro/db" || c.Backup.Restore.Stanza != "main" || c.repoPath() != "/ziro/db2" {
		t.Fatalf("restore: %+v", c.Backup)
	}
	if c.Image != src.Image || c.Database != src.Database || c.Version != src.Version {
		t.Fatal("the copy runs what the source ran")
	}
	if w.st.Secrets[c.backupSecret()]["PGBACKREST_REPO1_CIPHER_PASS"] != w.st.Secrets[src.backupSecret()]["PGBACKREST_REPO1_CIPHER_PASS"] {
		t.Fatal("the copy needs the source's passphrase")
	}
	w.step(5 * time.Second)
	g := c.entryGroup()
	var inits []string
	for _, m := range c.group(g).Members {
		inits = append(inits, m.ID+"="+m.Init)
		a := w.st.app(c.memberApp(g, m.ID))
		if a.Env["ZIRO_PG_RESTORE_PATH"] != "/ziro/db" || a.Env["ZIRO_PG_RESTORE_TARGET"] != "2026-10-21T11:00:00Z" || a.Env["ZIRO_PG_INIT"] != m.Init {
			t.Fatalf("%s env: %v", m.ID, a.Env)
		}
	}
	if strings.Join(inits, ",") != "m1=restore,m2=replica" {
		t.Fatalf("the primary restores, the replicas copy it: %v", inits)
	}
	// Disaster recovery: the source is gone, its repository is all there is.
	repo := testRepo()
	repo.Path = "/ziro/db"
	repo.Retention, repo.Full = 4, "0 1 * * 0"
	if _, err := pgRestore(w.st, pgRestoreOpts{Name: "db3", Repo: &repo, KeyID: "AKIAEXAMPLE", Secret: "secret"}, w.now); err == nil {
		t.Fatal("the passphrase is required")
	}
	c3, err := pgRestore(w.st, pgRestoreOpts{Name: "db3", Repo: &repo, KeyID: "AKIAEXAMPLE", Secret: "secret", Passkey: "p4ss", Image: testBackupImage, Target: "latest"}, w.now)
	if err != nil {
		t.Fatal(err)
	}
	if c3.Backup.Restore.Path != "/ziro/db" || c3.Backup.Restore.Target != "" || c3.repoPath() != "/ziro/db/db3" || w.st.Secrets[c3.backupSecret()]["PGBACKREST_REPO1_CIPHER_PASS"] != "p4ss" {
		t.Fatalf("dr restore: %+v %s", c3.Backup.Restore, c3.repoPath())
	}
	if _, err := pgRestore(w.st, pgRestoreOpts{Name: "db4", From: "nope"}, w.now); err == nil {
		t.Fatal("unknown source")
	}
	if _, ok := w.st.PG["db4"]; ok {
		t.Fatal("a failed restore leaves a cluster behind")
	}
}

func TestPGBackupOrdersAreValidated(t *testing.T) {
	for _, c := range []struct {
		op, arg string
		ok      bool
	}{
		{opStanza, "main", true}, {opStanza, "w1", true}, {opStanza, "main --repo1-path=/x", false}, {opStanza, "", false},
		{opBackup, "full", true}, {opBackup, "diff", true}, {opBackup, "incr", true}, {opBackup, "full --delta", false},
	} {
		if err := validPGCommand(c.op, c.arg); (err == nil) != c.ok {
			t.Errorf("%s %q: %v", c.op, c.arg, err)
		}
	}
}

func TestPGProbeReadsTheArchiver(t *testing.T) {
	r, err := parseProbe("0|0/151E2A8|1|0|0|0|0/151E2A8||1|250|893|9|2|35")
	if err != nil || r.ArchiveFailed != 2 || r.ArchivedAgo != 35 {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = parseProbe("0|0/151E2A8|1|0|0|0|0/151E2A8||1|250|893|9|0|-1") // nothing archived yet
	if err != nil || r.ArchivedAgo != -1 {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := parseProbe("0|0/151E2A8|1|0|0|0|0/151E2A8||1|250|893|9|-3|1"); err == nil {
		t.Fatal("a negative failure count is refused")
	}
}

func TestPGBackupMetrics(t *testing.T) {
	w := backupWorld(t)
	w.settle(4)
	g := w.cluster().group("main")
	g.Backup.Info = &PGBackupInfo{At: w.now, Backups: []PGBackupSummary{
		{Label: "20261021-110000F", Type: "full", Stop: w.now.Add(-time.Hour), Repo: 1000},
		{Label: "20261021-110000F_20261021-113000I", Type: "incr", Stop: w.now.Add(-10 * time.Minute), Repo: 24}}}
	g.primary().Probe.ArchivedAgo, g.primary().Probe.ArchiveFailed = 12, 2
	var m metricsWriter
	pgMetrics(&m, w.st, w.now)
	out := m.b.String()
	p := w.primaryOf("main")
	for _, want := range []string{
		`ziro_pg_backup_last_seconds{cluster="db",group="main",type="full"} 3600`,
		`ziro_pg_backup_last_seconds{cluster="db",group="main",type="incr"} 600`,
		`ziro_pg_backup_repository_bytes{cluster="db",group="main"} 1024`,
		`ziro_pg_archive_failed_total{cluster="db",group="main",member="` + p + `"} 2`,
		`ziro_pg_archive_last_seconds{cluster="db",group="main",member="` + p + `"} 12`,
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("metrics lack %s", want)
		}
	}
	if strings.Contains(out, `type="diff"`) {
		t.Fatal("no differential yet")
	}
}
