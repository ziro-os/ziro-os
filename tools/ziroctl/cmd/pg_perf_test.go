package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPGProbeWithMetricsFromPostgres16(t *testing.T) {
	// what pgProbeSQL returned on PostgreSQL 16 (a primary, no standbys)
	r, err := parseProbe("0|0/151E2A8|1|0|0|0|0/151E2A8||1|250|893|9")
	if err != nil || r.Recovery || r.Conns != 1 || r.MaxConns != 250 || r.Commits != 893 || r.XIDAge != 9 || r.SyncNames != "" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := parseProbe("0|0/151E2A8|1|0|0|0|0/151E2A8||1|250|-1|9"); err == nil {
		t.Fatal("a negative counter is refused")
	}
}

func TestPGTuningPerVersion(t *testing.T) {
	small, big := pgTuning(&Resources{Memory: "1Gi", CPUs: 1}, false, "17"), pgTuning(&Resources{Memory: "64Gi", CPUs: 32}, false, "17")
	for _, c := range []string{small, big} {
		for _, want := range []string{"max_worker_processes = 32\n", "max_connections = 200\n", "jit = off", "wal_compression = lz4",
			"shared_preload_libraries = 'pg_stat_statements,auto_explain'", "checkpoint_timeout = 15min", "idle_in_transaction_session_timeout = 30min"} {
			if !strings.Contains(c, want) {
				t.Errorf("tuning lacks %q", want)
			}
		}
	}
	if strings.Contains(small, "io_method") || !strings.Contains(pgTuning(nil, false, "18"), "io_method = worker") {
		t.Fatal("asynchronous I/O settings are for PostgreSQL 18 only")
	}
}

func TestPGParamsAreChecked(t *testing.T) {
	for _, c := range []struct{ k, v, cur string }{
		{"work_mem", "64MB", ""}, {"work_mem", "65536", ""}, {"statement_timeout", "30s", ""}, {"statement_timeout", "0", ""},
		{"jit", "on", ""}, {"log_statement", "ddl", ""}, {"random_page_cost", "1.5", ""}, {"max_connections", "300", "200"},
	} {
		if err := pgCheckParam(c.k, c.v, c.cur); err != nil {
			t.Errorf("%s=%s: %v", c.k, c.v, err)
		}
	}
	for _, c := range []struct{ k, v, cur string }{
		{"work_mem", "64MB'; drop table t; --", ""}, {"work_mem", "1PB", ""}, {"work_mem", "1kB", ""},
		{"statement_timeout", "forever", ""}, {"jit", "yes", ""}, {"log_statement", "everything", ""},
		{"synchronous_standby_names", "''", ""}, {"ssl", "off", ""}, {"primary_conninfo", "host=evil", ""}, {"listen_addresses", "*", ""},
		{"max_connections", "100", "200"}, {"max_connections", "5", ""},
	} {
		if err := pgCheckParam(c.k, c.v, c.cur); err == nil {
			t.Errorf("%s=%s accepted", c.k, c.v)
		}
	}
}

func TestPGSetReloadsWithoutRestartAndRollsRestartParams(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	revs := func() []int {
		var r []int
		for _, id := range []string{"m1", "m2", "m3"} {
			r = append(r, w.st.app(w.app("main", id)).Revision)
		}
		return r
	}
	before := revs()
	if err := pgSetParams(w.st, "db", map[string]string{"work_mem": "64MB", "statement_timeout": "30s"}); err != nil {
		t.Fatal(err)
	}
	content, hash := pgReloadParams(w.cluster())
	if !strings.Contains(content, "work_mem = '64MB'\n") || !strings.Contains(content, "statement_timeout = '30s'\n") {
		t.Fatalf("params.conf:\n%s", content)
	}
	if got := pgDynamic(w.st, w.app("main", "m2"))["params.conf"]; got != content {
		t.Fatalf("the members get the file while they run: %q", got)
	}
	w.settle(4)
	if !slices.Equal(revs(), before) {
		t.Fatal("reloadable parameters restarted a member")
	}
	for _, id := range []string{"m1", "m2", "m3"} {
		if w.member("main", id).Params != hash {
			t.Fatalf("%s did not reload (%v)", id, w.log)
		}
	}
	// a parameter that needs a restart rolls the members, primary last
	if err := pgSetParams(w.st, "db", map[string]string{"max_connections": "400"}); err != nil {
		t.Fatal(err)
	}
	if err := pgSetParams(w.st, "db", map[string]string{"max_connections": "300"}); err == nil {
		t.Fatal("max_connections went down")
	}
	if err := pgSetParams(w.st, "db", map[string]string{"work_mem": ""}); err != nil || w.cluster().Params["work_mem"] != "" {
		t.Fatalf("back to the default: %v", err)
	}
	if !strings.Contains(pgMemberApp(w.st, w.cluster(), &w.cluster().Groups[0], w.member("main", "m1")).ConfigFiles["postgresql.conf"], "max_connections = '400'") {
		t.Fatal("restart parameters go into postgresql.conf")
	}
	w.settle(40)
	after := revs()
	for i := range after {
		if after[i] == before[i] {
			t.Fatalf("member %d did not restart with max_connections: %v -> %v", i+1, before, after)
		}
	}
}

func TestPGResizeUpgradeRestart(t *testing.T) {
	w := newPGWorld(t, 3)
	c := w.create(pgCreateOpts{Replicas: 2})
	if err := pgResize(w.st, "db", &Resources{Memory: "lots"}); err == nil {
		t.Fatal("a bad size is refused")
	}
	if err := pgResize(w.st, "db", &Resources{Memory: "8Gi", CPUs: 4}); err != nil || c.Resources.Memory != "8Gi" {
		t.Fatal(err)
	}
	if err := pgUpgradeImage(w.st, "db", "docker.io/library/postgres:17.9"); err == nil {
		t.Fatal("an image without a digest is refused")
	}
	if err := pgUpgradeImage(w.st, "db", "docker.io/library/postgres:18.1@sha256:"+strings.Repeat("a", 64)); err == nil {
		t.Fatal("a major version change is refused")
	}
	img := "docker.io/library/postgres:17.9@sha256:" + strings.Repeat("b", 64)
	if err := pgUpgradeImage(w.st, "db", img); err != nil || c.Image != img {
		t.Fatal(err)
	}
	h := specHash(pgMemberApp(w.st, c, &c.Groups[0], &c.Groups[0].Members[0]))
	if err := pgRestartAll(w.st, "db"); err != nil || specHash(pgMemberApp(w.st, c, &c.Groups[0], &c.Groups[0].Members[0])) == h {
		t.Fatal("pg restart must change the members' spec (and so roll them)")
	}
}

func TestPGPoolerIsOnByDefaultWithItsOwnSecret(t *testing.T) {
	w := newPGWorld(t, 3)
	c := w.create(pgCreateOpts{Replicas: 1, AllowFrom: []string{"shop-web"}})
	w.settle(3)
	app := w.st.app(c.poolerApp())
	if app == nil || app.Replicas != 2 || app.Image != pgPoolerImage || app.Env["ZIRO_POOL_RW"] != "db-main-rw.cluster.ziro" || app.Env["ZIRO_POOL_RO"] != "db-main-ro.cluster.ziro" {
		t.Fatalf("pooler app: %+v", app)
	}
	if !slices.Contains(app.AllowFrom, "shop-web") {
		t.Fatal("the apps allowed to use the cluster may use the pooler")
	}
	sec := w.st.Secrets[c.poolerSecret()]
	if sec["POSTGRES_PASSWORD"] == "" || sec["PG_TLS_CERT"] == "" || sec["PG_SUPERUSER_PASSWORD"] != "" || sec["PG_REPL_PASSWORD"] != "" {
		t.Fatalf("the pooler's secret holds only what it needs: %d keys", len(sec))
	}
	if m := pgMemberApp(w.st, c, &c.Groups[0], &c.Groups[0].Members[0]); !slices.Contains(m.AllowFrom, c.poolerApp()) {
		t.Fatal("the members accept the pooler")
	}
	if u := pgPoolString(w.st, c, true); !strings.HasPrefix(u, "postgres://app:") || !strings.Contains(u, "@db-pool.cluster.ziro:5432/app_ro") {
		t.Fatalf("pool url: %s", u)
	}
	off := false
	if err := pgSetPooler(w.st, "db", &off, "", 0); err != nil {
		t.Fatal(err)
	}
	w.settle(1)
	if w.st.app(c.poolerApp()) != nil || w.st.Secrets[c.poolerSecret()] != nil {
		t.Fatal("a disabled pooler leaves nothing behind")
	}
	if err := pgSetPooler(w.st, "db", nil, "statement", 0); err == nil {
		t.Fatal("statement pooling is not offered (it breaks transactions)")
	}
	np := w.create(pgCreateOpts{Name: "nopool", Replicas: 1, NoPooler: true})
	if np.poolerOn() {
		t.Fatal("--no-pooler")
	}
}

func TestPGPoolerScriptWritesPgBouncerConfig(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	os.MkdirAll(bin, 0o755)
	// a stand-in pgbouncer that prints the configuration it was given
	os.WriteFile(filepath.Join(bin, "pgbouncer"), []byte("#!/bin/sh\nfor a; do last=$a; done\ncat \"$last\"\necho ARGS: \"$@\"\n"), 0o755)
	script := filepath.Join(dir, "pool.sh")
	os.WriteFile(script, []byte(pgPoolerScript), 0o755)
	cmd := exec.Command("sh", script)
	cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "ZIRO_POOL_DIR=" + filepath.Join(dir, "cfg"), "POSTGRES_DB=app", "POSTGRES_USER=app",
		"POSTGRES_PASSWORD=s3cret", "ZIRO_POOL_RW=db-main-rw.cluster.ziro", "ZIRO_POOL_RO=db-main-ro.cluster.ziro", "ZIRO_POOL_MODE=transaction",
		"ZIRO_POOL_SIZE=20", "ZIRO_POOL_CLIENTS=1000", "PG_TLS_CA=Q0E=", "PG_TLS_CERT=Q0VSVA==", "PG_TLS_KEY=S0VZ"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	for _, want := range []string{"app = host=db-main-rw.cluster.ziro port=5432 dbname=app", "app_ro = host=db-main-ro.cluster.ziro port=5432 dbname=app",
		"pool_mode = transaction", "default_pool_size = 20", "auth_type = scram-sha-256", "server_tls_sslmode = verify-ca", "client_tls_sslmode = prefer", "dns_max_ttl = 5"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("pgbouncer.ini lacks %q:\n%s", want, out)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "cfg", "userlist.txt")); string(b) != "\"app\" \"s3cret\"\n" {
		t.Fatalf("userlist: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "cfg", "server.key")); string(b) != "KEY" {
		t.Fatal("the TLS key is written")
	}
}

func TestPGLoadAlerts(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	c := &PGCluster{Name: "db"}
	g := &PGGroup{Members: []PGMember{{ID: "m1", Role: pgPrimary, Probe: PGProbe{At: now, OK: true, Conns: 185, MaxConns: 200, XIDAge: 1_600_000_000}}}}
	pgLoadAlerts(c, g, now)
	msgs := ""
	for _, e := range g.Events {
		msgs += e.Alert + ": " + e.Msg + "\n"
	}
	if !strings.Contains(msgs, "185 of 200 connections") || !strings.Contains(msgs, "pg pool db --enable") || !strings.Contains(msgs, "high: m1: the oldest unfrozen") {
		t.Fatalf("alerts:\n%s", msgs)
	}
}
