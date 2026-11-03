package cmd

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPGRolesAndDatabasesAreAppliedOnThePrimary(t *testing.T) {
	w := newPGWorld(t, 3)
	c := w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	if err := pgSetRole(w.st, "db", PGRole{Name: "web", Access: "readwrite"}); err != nil {
		t.Fatal(err)
	}
	if err := pgSetRole(w.st, "db", PGRole{Name: "reports", Access: "readonly", Database: "analytics"}); err == nil {
		t.Fatal("a role may only name one of the cluster's databases")
	}
	if err := pgSetDatabase(w.st, "db", PGDatabase{Name: "analytics", Owner: "web", Extensions: []string{"pg_trgm", "citext", "pg_trgm"}}); err != nil {
		t.Fatal(err)
	}
	if err := pgSetRole(w.st, "db", PGRole{Name: "reports", Access: "readonly", Database: "analytics"}); err != nil {
		t.Fatal(err)
	}
	if err := pgSetDatabase(w.st, "db", PGDatabase{Name: "app", Extensions: []string{"pgcrypto"}}); err != nil {
		t.Fatal("the cluster's own database can get extensions")
	}
	w.settle(12)
	primary := w.app("main", w.primaryOf("main"))
	var roleOrders, dbOrders []string
	for _, l := range w.log {
		f := strings.Fields(l)
		if len(f) < 3 {
			continue
		}
		switch f[1] {
		case opRole:
			if f[0] != primary {
				t.Fatalf("a role order went to %s, not the primary", f[0])
			}
			if strings.Contains(l, w.st.Secrets[c.roleSecret("web")]["PGPASSWORD"]) {
				t.Fatal("an order carries the plaintext password")
			}
			roleOrders = append(roleOrders, f[2][:strings.Index(f[2], ":SCRAM")])
		case opDatabase:
			dbOrders = append(dbOrders, f[2])
		}
	}
	if !slices.Equal(roleOrders, []string{"web:readwrite", "reports:readonly"}) {
		t.Fatalf("role orders: %v", roleOrders)
	}
	slices.Sort(dbOrders) // analytics waits for its owner; app goes when it can
	if !slices.Equal(dbOrders, []string{"analytics:web:citext,pg_trgm", "app:app:pgcrypto"}) {
		t.Fatalf("database orders: %v", dbOrders)
	}
	for _, r := range pgRoleRows(w.st, c) {
		if r.State != "ready" {
			t.Fatalf("%s %s is %s", r.Kind, r.Name, r.State)
		}
	}
	// Nothing more once applied.
	n := len(w.log)
	w.settle(6)
	for _, l := range w.log[n:] {
		if f := strings.Fields(l); len(f) > 1 && (f[1] == opRole || f[1] == opDatabase) {
			t.Fatalf("applied again: %s", l)
		}
	}
	// Credentials: a secret per role, and the application user's connection strings.
	sec := w.st.Secrets[c.roleSecret("reports")]
	if len(sec["PGPASSWORD"]) != 32 || !strings.HasPrefix(sec["DATABASE_URL"], "postgres://reports:"+sec["PGPASSWORD"]+"@db-rw.") ||
		!strings.Contains(sec["DATABASE_URL"], "/analytics") || !strings.Contains(sec["DATABASE_URL_RO"], "@db-ro.") {
		t.Fatalf("role secret: %v", sec)
	}
	url := w.st.Secrets[c.urlSecret()]
	if !strings.HasPrefix(url["DATABASE_URL"], "postgres://app:") || url["DATABASE_POOL_URL"] == "" {
		t.Fatalf("url secret: %v", url)
	}
	// Removing a role locks it out and deletes its credentials; one that owns a database cannot go.
	if err := pgRemoveRole(w.st, "db", "web"); err == nil {
		t.Fatal("removed the owner of a database")
	}
	if err := pgRemoveRole(w.st, "db", "reports"); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.st.Secrets[c.roleSecret("reports")]; ok {
		t.Fatal("the removed role's credentials stay")
	}
	w.settle(4)
	if !w.logHas(" roleoff reports") || len(c.RolesOff) != 0 {
		t.Fatalf("not locked out: %v %v", c.RolesOff, w.log[len(w.log)-3:])
	}
	if err := pgRemoveDatabase(w.st, "db", "analytics"); err != nil || c.database("analytics") != nil {
		t.Fatalf("unmanage: %v", err)
	}
}

func TestPGRoleValidation(t *testing.T) {
	c := &PGCluster{Name: "db", User: "app", Database: "app"}
	for _, r := range []PGRole{
		{Name: "postgres", Access: "readwrite"}, {Name: "replicator", Access: "readonly"}, {Name: "app", Access: "readwrite"},
		{Name: "pg_monitor", Access: "readonly"}, {Name: "ziro_x", Access: "readonly"}, {Name: "Web", Access: "readwrite"},
		{Name: `web"; drop`, Access: "readwrite"}, {Name: "web", Access: "superuser"},
	} {
		if pgCheckRole(c, r) == nil {
			t.Errorf("%+v accepted", r)
		}
	}
	for _, d := range []PGDatabase{
		{Name: "postgres"}, {Name: "template1"}, {Name: "app", Owner: "web"}, {Name: "x", Owner: "nobody"},
		{Name: "x", Extensions: []string{"plpython3u"}}, {Name: "x", Extensions: []string{"citus"}},
	} {
		if pgCheckDatabase(c, d) == nil {
			t.Errorf("%+v accepted", d)
		}
	}
	v, _ := scramVerifier("pw", []byte("0123456789abcdef"))
	for arg, ok := range map[string]bool{
		"web:readwrite:" + v: true, "web:readonly:" + v: true, "web:owner:" + v: false, "postgres:readwrite:" + v: false,
		"web:readwrite:plain": false, `web":readwrite:` + v: false,
	} {
		if (validPGCommand(opRole, arg) == nil) != ok {
			t.Errorf("role %q", arg)
		}
	}
	for arg, ok := range map[string]bool{
		"analytics:web:pg_trgm,citext": true, "analytics:web:": true, "postgres:web:": false, "x:web:plpython3u": false,
		"x:web:pg_trgm;drop": false, "x:postgres:": false,
	} {
		if (validPGCommand(opDatabase, arg) == nil) != ok {
			t.Errorf("database %q", arg)
		}
	}
}

func TestPGRoleStepsAndTolerance(t *testing.T) {
	v, _ := scramVerifier("pw", []byte("0123456789abcdef"))
	steps, err := pgSteps(PGOrder{Container: "zc-pgc-db-main-m1-0", Op: opRole, Arg: "reports:readonly:" + v})
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(steps[0], " ")
	for _, want := range []string{`create role "reports"`, `nosuperuser`, `password '` + v + `'`, `grant pg_read_all_data to "reports"`, `revoke pg_write_all_data from "reports"`} {
		if !strings.Contains(all, want) {
			t.Errorf("role steps lack %q", want)
		}
	}
	steps, _ = pgSteps(PGOrder{Container: "zc-pgc-db-main-m1-0", Op: opDatabase, Arg: "analytics:web:pg_trgm,uuid-ossp"})
	if len(steps) != 3 || !strings.Contains(strings.Join(steps[2], " "), `-d analytics`) || !strings.Contains(strings.Join(steps[2], " "), `create extension if not exists "uuid-ossp"`) {
		t.Fatalf("database steps: %v", steps)
	}
	// An existing database, and a role already gone, are what the order wanted.
	var ran int
	run := func(_ context.Context, args ...string) (string, error) {
		ran++
		if ran == 1 && strings.Contains(strings.Join(args, " "), "create database") {
			return `ERROR:  database "analytics" already exists`, errors.New("exit status 1")
		}
		return "", nil
	}
	if err := pgExecute(context.Background(), run, PGOrder{Container: "zc-pgc-db-main-m1-0", Op: opDatabase, Arg: "analytics:web:pg_trgm"}); err != nil || ran != 3 {
		t.Fatalf("existing database: %v after %d steps", err, ran)
	}
	gone := func(context.Context, ...string) (string, error) {
		return `ERROR:  role "reports" does not exist`, errors.New("exit status 1")
	}
	if err := pgExecute(context.Background(), gone, PGOrder{Container: "zc-pgc-db-main-m1-0", Op: opRoleOff, Arg: "reports"}); err != nil {
		t.Fatal(err)
	}
	fail := func(context.Context, ...string) (string, error) {
		return `ERROR:  permission denied`, errors.New("exit status 1")
	}
	if err := pgExecute(context.Background(), fail, PGOrder{Container: "zc-pgc-db-main-m1-0", Op: opDatabase, Arg: "analytics:web:"}); err == nil {
		t.Fatal("a real failure is not tolerated")
	}
}

func TestPGRoleFailureIsRetriedAndAlerts(t *testing.T) {
	w := newPGWorld(t, 3)
	c := w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	w.fails[opRole] = true
	if err := pgSetRole(w.st, "db", PGRole{Name: "web", Access: "readwrite"}); err != nil {
		t.Fatal(err)
	}
	w.settle(8) // 40 s: one try, then it waits a minute
	tries := 0
	for _, l := range w.log {
		if strings.Contains(l, " role web:") {
			tries++
		}
	}
	if tries != 1 || !strings.Contains(w.events("main"), "web: simulated failure") {
		t.Fatalf("%d tries; events %s", tries, w.events("main"))
	}
	if r := pgRoleRows(w.st, c); r[1].State != "failing" {
		t.Fatalf("state %s", r[1].State)
	}
	delete(w.fails, opRole)
	w.advance(80 * time.Second)
	if r := pgRoleRows(w.st, c); r[1].State != "ready" {
		t.Fatalf("not retried: %s", r[1].State)
	}
}

func TestPGApplyRolesAndDatabases(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	// The role connects to a database the file adds, owned by another role the file adds.
	cfg := parsePGFile(t, `
postgres:
  version: 1
  name: db
  roles:
    - {name: reports, access: readonly, database: analytics}
    - {name: etl}
  databases:
    - {name: analytics, owner: etl, extensions: [pg_trgm]}
`)
	plan := pgApplySpec(w.st, cfg, pgApplyKeys{}, w.now)
	if len(plan.refused()) > 0 {
		t.Fatalf("refused: %v", plan.refused())
	}
	c := w.cluster()
	if c.role("reports") == nil || c.role("etl").Access != "readwrite" || c.database("analytics").Owner != "etl" {
		t.Fatalf("roles %v databases %v", c.Roles, c.Databases)
	}
	if again := pgApplySpec(w.st, cfg, pgApplyKeys{}, w.now); again.changed() {
		t.Fatalf("not idempotent: %v", planLines(again))
	}
	y := pgSpecOf(c)
	if len(y.Postgres.Roles) != 2 || len(y.Postgres.Databases) != 1 {
		t.Fatalf("pg get: %+v", y.Postgres)
	}
	// An empty list removes them; a role that owns a database goes only with it.
	out := pgApplySpec(w.st, parsePGFile(t, "postgres: {version: 1, name: db, roles: [], databases: []}"), pgApplyKeys{}, w.now)
	if len(out.refused()) > 0 || len(c.Roles) != 0 || len(c.Databases) != 0 || len(c.RolesOff) != 2 {
		t.Fatalf("removal: %v roles %v off %v", planLines(out), c.Roles, c.RolesOff)
	}
	bad := pgApplySpec(w.st, parsePGFile(t, "postgres: {version: 1, name: db, databases: [{name: x, owner: ghost}]}"), pgApplyKeys{}, w.now)
	if len(bad.refused()) != 1 {
		t.Fatalf("an unknown owner: %v", planLines(bad))
	}
}

func TestPGConnectAppAndPurge(t *testing.T) {
	w := newPGWorld(t, 3)
	c := w.create(pgCreateOpts{Replicas: 2})
	if err := pgSetRole(w.st, "db", PGRole{Name: "web", Access: "readwrite"}); err != nil {
		t.Fatal(err)
	}
	s, err := pgConnectApp(w.st, "db:web", "shop-web")
	if err != nil || s != c.roleSecret("web") || !slices.Contains(c.AllowFrom, "shop-web") || w.st.Secrets[s]["DATABASE_URL"] == "" {
		t.Fatalf("%s %v allow %v", s, err, c.AllowFrom)
	}
	if s, err := pgConnectApp(w.st, "db", "shop-worker"); err != nil || s != c.urlSecret() {
		t.Fatal(err)
	}
	for _, bad := range []string{"nope", "db:ghost"} {
		if _, err := pgConnectApp(w.st, bad, "x"); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	w.st.Secrets["pg-dbx"] = map[string]string{"K": "v"} // another cluster's, not this one's
	if err := pgDelete(w.st, "db", true); err != nil {
		t.Fatal(err)
	}
	for name := range w.st.Secrets {
		if name == "pg-db" || strings.HasPrefix(name, "pg-db-") {
			t.Errorf("purge left %s", name)
		}
	}
	if w.st.Secrets["pg-dbx"] == nil {
		t.Fatal("purge deleted another cluster's secret")
	}
}

func TestPGTopViewAndKeys(t *testing.T) {
	w := newPGWorld(t, 3)
	w.create(pgCreateOpts{Replicas: 2})
	w.settle(8)
	v := newPGTopView()
	var acted []string
	v.act = func(audit, cluster string, fn func(*ClusterState, time.Time) error) error {
		acted = append(acted, audit)
		return fn(w.st, w.now)
	}
	for i := range w.cluster().Groups[0].Members {
		w.cluster().Groups[0].Members[i].Probe.Commits = 1000
	}
	v.sample(w.st, w.now)
	for i := range w.cluster().Groups[0].Members {
		w.cluster().Groups[0].Members[i].Probe.Commits = 1100
	}
	v.sample(w.st, w.now.Add(2*time.Second))
	var buf bytes.Buffer
	v.render(&buf, w.st, w.now, 140, 30)
	plain := ansiCursorRe.ReplaceAllString(buf.String(), "")
	if !strings.Contains(plain, "db ") || !strings.Contains(plain, "healthy") || !strings.Contains(plain, "150.0") {
		t.Fatalf("fleet:\n%s", plain)
	}
	v.key("enter", w.st, w.now)
	v.key("down", w.st, w.now) // the first replica
	v.render(&buf, w.st, w.now, 140, 30)
	if plain = ansiCursorRe.ReplaceAllString(buf.String(), ""); !strings.Contains(plain, "PostgreSQL 17") || !strings.Contains(plain, "> main  m2") {
		t.Fatalf("cluster:\n%s", plain)
	}
	v.key("s", w.st, w.now)
	if v.confirm == nil || v.confirm.label != "switchover to m2" {
		t.Fatalf("confirm %+v", v.confirm)
	}
	v.key("n", w.st, w.now) // cancelled
	if len(acted) != 0 || v.status != "cancelled" {
		t.Fatal("ran without confirmation")
	}
	v.key("s", w.st, w.now)
	v.key("y", w.st, w.now)
	if len(acted) != 1 || w.cluster().Groups[0].Switch == nil || w.cluster().Groups[0].Switch.To != "m2" {
		t.Fatalf("switchover: %v %+v", acted, w.cluster().Groups[0].Switch)
	}
	v.key("b", w.st, w.now)
	if v.confirm != nil || !strings.Contains(v.status, "backups are off") {
		t.Fatal("backup without backups")
	}
	v.key("esc", w.st, w.now)
	if v.cluster != "" {
		t.Fatal("esc goes back to the fleet")
	}
	if !v.key("q", w.st, w.now) {
		t.Fatal("q quits")
	}
	// Arrow keys arrive as escape sequences.
	in, out := make(chan byte, 8), make(chan string, 8)
	for _, b := range []byte{27, '[', 'B', 'j', '\r', 27} {
		in <- b
	}
	close(in)
	go pgTopKeys(in, out)
	var got []string
	for k := range out {
		got = append(got, k)
	}
	if !slices.Equal(got, []string{"down", "j", "enter", "esc"}) {
		t.Fatalf("keys %v", got)
	}
}
