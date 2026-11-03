package cmd

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// Roles and databases (pg role, pg db, and the roles:/databases: sections of a cluster file).
//
// A role is a login for an app: readwrite (it reads and writes every table, through PostgreSQL's
// pg_read_all_data and pg_write_all_data) or readonly (pg_read_all_data only). Its password is generated
// and kept in its own cluster secret, pg-<cluster>-role-<role>, with ready connection strings, so an app
// gets only its own credentials (apps deploy --pg shop:web). The primary receives only the password's
// SCRAM verifier, as with pg rotate-password. A role removed from the cluster can no longer log in
// (NOLOGIN); its objects and grants stay.
//
// A database has an owner (the application user or a role; the owner can create tables in it) and
// extensions from a fixed list. A database removed from the cluster is no longer managed; it is never
// dropped.
//
// The controller applies one change per pass, on the primary of the entry group (the Citus coordinator),
// and records what it applied (PGCluster.Applied), so it converges without repeating itself. A failed
// change is retried after a minute and raises an alert at most every 15 minutes.

const (
	opRole     = "role"     // create or alter a login role; argument "name:access:SCRAM verifier"
	opRoleOff  = "roleoff"  // ALTER ROLE ... NOLOGIN for a role removed from the cluster; argument the name
	opDatabase = "database" // create a database if missing, set its owner and extensions; argument "name:owner:ext,ext"
)

// PGRole is a login role for apps.
type PGRole struct {
	Name     string `json:"name"`
	Access   string `json:"access"`             // readwrite or readonly
	Database string `json:"database,omitempty"` // the database its connection strings name ("" = the cluster's)
}

// PGDatabase is a database the cluster manages besides its own.
type PGDatabase struct {
	Name       string   `json:"name"`
	Owner      string   `json:"owner,omitempty"` // "" = the application user
	Extensions []string `json:"extensions,omitempty"`
}

// pgExtensions are the extensions a database may have: the ones the official image ships (contrib)
// that need no server library preloaded.
var pgExtensions = map[string]bool{
	"amcheck": true, "bloom": true, "btree_gin": true, "btree_gist": true, "citext": true, "cube": true,
	"dict_int": true, "earthdistance": true, "fuzzystrmatch": true, "hstore": true, "intarray": true, "isn": true,
	"lo": true, "ltree": true, "pg_buffercache": true, "pg_prewarm": true, "pg_stat_statements": true,
	"pg_trgm": true, "pgcrypto": true, "pgstattuple": true, "postgres_fdw": true, "seg": true, "tablefunc": true,
	"tcn": true, "unaccent": true, "uuid-ossp": true,
}

var pgReservedRoleRe = regexp.MustCompile(`^(postgres|replicator|pg_.*|ziro_.*)$`)

func pgReservedDB(name string) bool {
	return name == "postgres" || name == "template0" || name == "template1"
}

func (c *PGCluster) roleSecret(role string) string { return pgSecretPrefix + c.Name + "-role-" + role }
func (c *PGCluster) urlSecret() string             { return pgSecretPrefix + c.Name + "-url" }

func (c *PGCluster) role(name string) *PGRole {
	for i := range c.Roles {
		if c.Roles[i].Name == name {
			return &c.Roles[i]
		}
	}
	return nil
}

func (c *PGCluster) database(name string) *PGDatabase {
	for i := range c.Databases {
		if c.Databases[i].Name == name {
			return &c.Databases[i]
		}
	}
	return nil
}

func pgCheckRole(c *PGCluster, r PGRole) error {
	if !pgIdentRe.MatchString(r.Name) || pgReservedRoleRe.MatchString(r.Name) || r.Name == c.User {
		return fmt.Errorf("role %q: a lower-case identifier that is not postgres, replicator, the application user or pg_/ziro_", r.Name)
	}
	if r.Access != "readwrite" && r.Access != "readonly" {
		return fmt.Errorf("role %s: access is readwrite or readonly", r.Name)
	}
	if r.Database != "" && r.Database != c.Database && c.database(r.Database) == nil {
		return fmt.Errorf("role %s: database %s is not one of the cluster's", r.Name, r.Database)
	}
	return nil
}

func pgCheckDatabase(c *PGCluster, d PGDatabase) error {
	if !pgIdentRe.MatchString(d.Name) || pgReservedDB(d.Name) {
		return fmt.Errorf("database %q: a lower-case identifier that is not postgres or a template", d.Name)
	}
	if c.Citus != "" && d.Name != c.Database {
		return fmt.Errorf("database %s: a sharded cluster has only its own database (%s)", d.Name, c.Database)
	}
	switch {
	case d.Owner == "" || d.Owner == c.User:
	case d.Name == c.Database:
		return fmt.Errorf("database %s belongs to the application user %s", d.Name, c.User)
	case c.role(d.Owner) == nil:
		return fmt.Errorf("database %s: owner %s is not one of the cluster's roles", d.Name, d.Owner)
	}
	for _, e := range d.Extensions {
		if !pgExtensions[e] {
			return fmt.Errorf("database %s: extension %q is not available (%s)", d.Name, e, strings.Join(pgExtensionNames(), ", "))
		}
	}
	return nil
}

func pgExtensionNames() []string {
	out := make([]string, 0, len(pgExtensions))
	for e := range pgExtensions {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// ---- operations ----

// pgSetRole adds a role or changes its access.
func pgSetRole(st *ClusterState, name string, r PGRole) error {
	c, err := pgCluster(st, name)
	if err != nil {
		return err
	}
	if err := pgCheckRole(c, r); err != nil {
		return err
	}
	if cur := c.role(r.Name); cur != nil {
		*cur = r
	} else {
		c.Roles = append(c.Roles, r)
	}
	c.RolesOff = slices.DeleteFunc(c.RolesOff, func(n string) bool { return n == r.Name })
	return nil
}

// pgRemoveRole takes a role off the cluster: it can no longer log in, and its credentials are deleted.
func pgRemoveRole(st *ClusterState, name, role string) error {
	c, err := pgCluster(st, name)
	if err != nil {
		return err
	}
	if c.role(role) == nil {
		return fmt.Errorf("%s has no role %s", name, role)
	}
	for _, d := range c.Databases {
		if d.Owner == role {
			return fmt.Errorf("role %s owns database %s: give it another owner first", role, d.Name)
		}
	}
	c.Roles = slices.DeleteFunc(c.Roles, func(r PGRole) bool { return r.Name == role })
	c.RolesOff = append(c.RolesOff, role)
	delete(c.Applied, "role:"+role)
	delete(st.Secrets, c.roleSecret(role))
	return nil
}

// pgSetDatabase adds a database or changes its owner and extensions.
func pgSetDatabase(st *ClusterState, name string, d PGDatabase) error {
	c, err := pgCluster(st, name)
	if err != nil {
		return err
	}
	if err := pgCheckDatabase(c, d); err != nil {
		return err
	}
	d.Extensions = slices.Clone(d.Extensions)
	sort.Strings(d.Extensions)
	d.Extensions = slices.Compact(d.Extensions)
	if cur := c.database(d.Name); cur != nil {
		*cur = d
	} else {
		c.Databases = append(c.Databases, d)
	}
	return nil
}

// pgRemoveDatabase stops managing a database; it is not dropped.
func pgRemoveDatabase(st *ClusterState, name, db string) error {
	c, err := pgCluster(st, name)
	if err != nil {
		return err
	}
	if c.database(db) == nil {
		return fmt.Errorf("%s does not manage a database %s", name, db)
	}
	for _, r := range c.Roles {
		if r.Database == db {
			return fmt.Errorf("role %s connects to %s: change its database first", r.Name, db)
		}
	}
	c.Databases = slices.DeleteFunc(c.Databases, func(d PGDatabase) bool { return d.Name == db })
	delete(c.Applied, "db:"+db)
	return nil
}

// ---- secrets ----

// pgRoleURL is a connection string for user (password pw) to db on the read-write or read-only name.
func pgRoleURL(st *ClusterState, c *PGCluster, user, pw, db string, ro bool) string {
	host := c.Name + "-rw"
	if ro {
		host = c.Name + "-ro"
	}
	u := fmt.Sprintf("postgres://%s:%s@%s.%s:%s/%s", user, pw, host, meshDomain, pgPort, db)
	if pgTLSEnabled(st, c) {
		u += "?sslmode=require"
	}
	return u
}

// pgEnsureRoleSecrets keeps the credentials secrets in step: one per role (its generated password and
// connection strings) and one with the application user's connection strings (pg-<cluster>-url), which
// follow a password change. Secrets of removed roles are deleted.
func pgEnsureRoleSecrets(st *ClusterState, c *PGCluster) {
	set := func(name string, want map[string]string) {
		cur := st.Secrets[name]
		same := len(cur) == len(want)
		for k, v := range want {
			same = same && cur[k] == v
		}
		if !same {
			st.Secrets[name] = want
		}
	}
	main := st.Secrets[c.secretName()]
	if pw := main["POSTGRES_PASSWORD"]; pw != "" {
		want := map[string]string{
			"DATABASE_URL":    pgRoleURL(st, c, c.User, pw, c.Database, false),
			"DATABASE_URL_RO": pgRoleURL(st, c, c.User, pw, c.Database, true),
		}
		if c.poolerOn() {
			want["DATABASE_POOL_URL"] = pgPoolString(st, c, false)
			want["DATABASE_POOL_URL_RO"] = pgPoolString(st, c, true)
		}
		set(c.urlSecret(), want)
	}
	keep := map[string]bool{}
	for _, r := range c.Roles {
		name := c.roleSecret(r.Name)
		keep[name] = true
		pw := st.Secrets[name]["PGPASSWORD"]
		if pw == "" {
			var err error
			if pw, err = genSecret("alnum:32"); err != nil {
				continue
			}
		}
		db := r.Database
		if db == "" {
			db = c.Database
		}
		set(name, map[string]string{
			"PGPASSWORD":      pw,
			"DATABASE_URL":    pgRoleURL(st, c, r.Name, pw, db, false),
			"DATABASE_URL_RO": pgRoleURL(st, c, r.Name, pw, db, true),
		})
	}
	prefix := pgSecretPrefix + c.Name + "-role-"
	for name := range st.Secrets {
		if strings.HasPrefix(name, prefix) && !keep[name] {
			delete(st.Secrets, name)
		}
	}
}

// ---- reconciling ----

func pgHash(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:8])
}

// pgRoleWant is what applying a role means, as an applied-state key and hash (the password is part of
// it, so a new password is applied again).
func pgRoleWant(st *ClusterState, c *PGCluster, r PGRole) (key, hash, pw string) {
	pw = st.Secrets[c.roleSecret(r.Name)]["PGPASSWORD"]
	return "role:" + r.Name, pgHash(r.Name, r.Access, pw), pw
}

func pgDatabaseWant(c *PGCluster, d PGDatabase) (key, hash, owner string) {
	owner = d.Owner
	if owner == "" {
		owner = c.User
	}
	return "db:" + d.Name, pgHash(d.Name, owner, strings.Join(d.Extensions, ",")), owner
}

// pgRolesPass issues the next role or database change on the entry group's primary.
func pgRolesPass(st *ClusterState, c *PGCluster, now time.Time) {
	if len(c.Roles) == 0 && len(c.Databases) == 0 && len(c.RolesOff) == 0 {
		return
	}
	g := c.group(c.entryGroup())
	if g == nil || g.Switch != nil || g.promoting() != nil {
		return
	}
	p := g.primary()
	if p == nil || !p.fresh(now) || p.Probe.Recovery || p.Cmd != nil {
		return
	}
	retry := func(key string) bool {
		t, ok := g.Notes["reconcile-failed-"+key]
		return !ok || now.Sub(t) > time.Minute
	}
	for _, name := range c.RolesOff {
		if retry("roleoff:" + name) {
			p.issue(opRoleOff, name, g.Epoch, now)
			return
		}
	}
	for _, r := range c.Roles {
		key, hash, pw := pgRoleWant(st, c, r)
		if pw == "" || c.Applied[key] == hash || !retry(key) {
			continue
		}
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return
		}
		verifier, err := scramVerifier(pw, salt)
		if err != nil {
			return
		}
		if p.issue(opRole, r.Name+":"+r.Access+":"+verifier, g.Epoch, now) {
			pgIssued(c, key, hash)
		}
		return
	}
	for _, d := range c.Databases {
		key, hash, owner := pgDatabaseWant(c, d)
		if c.Applied[key] == hash || !retry(key) {
			continue
		}
		if owner != c.User && c.Applied["role:"+owner] == "" {
			continue // its owner first
		}
		if p.issue(opDatabase, d.Name+":"+owner+":"+strings.Join(d.Extensions, ","), g.Epoch, now) {
			pgIssued(c, key, hash)
		}
		return
	}
}

func pgIssued(c *PGCluster, key, hash string) {
	if c.Issued == nil {
		c.Issued = map[string]string{}
	}
	c.Issued[key] = hash
}

// pgRolesSettle records the outcome of a role or database order.
func pgRolesSettle(c *PGCluster, g *PGGroup, cmd *PGCommand, now time.Time) {
	var key, what string
	name, rest, _ := strings.Cut(cmd.Arg, ":")
	switch cmd.Op {
	case opRoleOff:
		key, what = "roleoff:"+name, "role "+name+" can no longer log in"
	case opRole:
		access, _, _ := strings.Cut(rest, ":")
		key, what = "role:"+name, fmt.Sprintf("role %s is ready (%s)", name, access)
	case opDatabase:
		key, what = "db:"+name, "database "+name+" is ready"
	}
	hash := c.Issued[key]
	delete(c.Issued, key)
	if g.Notes == nil {
		g.Notes = map[string]time.Time{}
	}
	if !cmd.OK {
		g.Notes["reconcile-failed-"+key] = now
		if g.last(now, 15*time.Minute, "reconcile-alert-"+key) {
			g.alert(now, "warning", "%s: %s", strings.TrimPrefix(strings.TrimPrefix(key, "role:"), "db:"), cmd.Msg)
		}
		return
	}
	delete(g.Notes, "reconcile-failed-"+key)
	if cmd.Op == opRoleOff {
		c.RolesOff = slices.DeleteFunc(c.RolesOff, func(n string) bool { return n == name })
	} else if hash != "" {
		if c.Applied == nil {
			c.Applied = map[string]string{}
		}
		c.Applied[key] = hash
	}
	g.note(now, "%s", what)
}

// pgRoleState is how far a role or database is: applied, pending or failing.
func pgRoleState(st *ClusterState, c *PGCluster, key, hash string) string {
	g := c.group(c.entryGroup())
	switch {
	case c.Applied[key] == hash:
		return "ready"
	case g != nil && !g.Notes["reconcile-failed-"+key].IsZero():
		return "failing"
	}
	return "pending"
}

// ---- agent side ----

// validRoleArg checks opRole's "name:access:verifier".
func validRoleArg(arg string) error {
	parts := strings.SplitN(arg, ":", 3)
	if len(parts) != 3 || !pgIdentRe.MatchString(parts[0]) || pgReservedRoleRe.MatchString(parts[0]) ||
		(parts[1] != "readwrite" && parts[1] != "readonly") || !pgVerifierRe.MatchString(parts[2]) {
		return fmt.Errorf("invalid role order")
	}
	return nil
}

// validDatabaseArg checks opDatabase's "name:owner:ext,ext".
func validDatabaseArg(arg string) error {
	parts := strings.SplitN(arg, ":", 3)
	if len(parts) != 3 || !pgIdentRe.MatchString(parts[0]) || pgReservedDB(parts[0]) || !pgIdentRe.MatchString(parts[1]) ||
		pgReservedRoleRe.MatchString(parts[1]) {
		return fmt.Errorf("invalid database order")
	}
	if parts[2] != "" {
		for _, e := range strings.Split(parts[2], ",") {
			if !pgExtensions[e] {
				return fmt.Errorf("invalid database order: extension %q", e)
			}
		}
	}
	return nil
}

// pgRoleSteps are the agent's statements for the role orders (arguments already validated: identifiers
// are lower-case words, the verifier a SCRAM string, extensions from the fixed list).
func pgRoleSteps(c string, o PGOrder) [][]string {
	switch o.Op {
	case opRole:
		parts := strings.SplitN(o.Arg, ":", 3)
		name, access, verifier := parts[0], parts[1], parts[2]
		write := `revoke pg_write_all_data from "` + name + `"`
		if access == "readwrite" {
			write = `grant pg_write_all_data to "` + name + `"`
		}
		return [][]string{psqlArgs(c,
			`do $$begin if not exists (select from pg_roles where rolname = '`+name+`') then create role "`+name+`"; end if; end$$`,
			`alter role "`+name+`" with login nosuperuser nocreatedb nocreaterole noreplication nobypassrls password '`+verifier+`'`,
			`grant pg_read_all_data to "`+name+`"`,
			write)}
	case opRoleOff:
		return [][]string{psqlArgs(c, `alter role "`+o.Arg+`" nologin`)}
	case opDatabase:
		parts := strings.SplitN(o.Arg, ":", 3)
		name, owner := parts[0], parts[1]
		steps := [][]string{
			psqlArgs(c, `create database "`+name+`" owner "`+owner+`"`), // "already exists" is fine (pgExecute)
			psqlArgs(c, `alter database "`+name+`" owner to "`+owner+`"`),
		}
		if parts[2] != "" {
			var sqls []string
			for _, e := range strings.Split(parts[2], ",") {
				sqls = append(sqls, `create extension if not exists "`+e+`"`)
			}
			steps = append(steps, psqlDB(c, name, sqls...))
		}
		return steps
	}
	return nil
}

// pgRoleStepTolerated: a step whose failure is the state it wanted (the database exists, the role to
// lock out is gone).
func pgRoleStepTolerated(op string, step int, out string) bool {
	return op == opDatabase && step == 0 && strings.Contains(out, "already exists") ||
		op == opRoleOff && strings.Contains(out, "does not exist")
}

// pgConnectApp lets a cluster app use a Postgres cluster ("shop", or "shop:role" for a role's own
// login): the app may connect, and the secret with its connection strings is returned for the app to
// load (DATABASE_URL, DATABASE_URL_RO, and the pooled ones for the application user).
func pgConnectApp(st *ClusterState, ref, app string) (string, error) {
	cluster, role, _ := strings.Cut(ref, ":")
	c, err := pgCluster(st, cluster)
	if err != nil {
		return "", fmt.Errorf("--pg %s: %v", ref, err)
	}
	if role != "" && c.role(role) == nil {
		return "", fmt.Errorf("--pg %s: %s has no role %s (ziroctl pg role %s %s)", ref, cluster, role, cluster, role)
	}
	if !slices.Contains(c.AllowFrom, app) && !slices.Contains(c.AllowFrom, "*") {
		c.AllowFrom = append(c.AllowFrom, app)
	}
	pgEnsureRoleSecrets(st, c) // the secret exists before the app is validated against it
	if role != "" {
		return c.roleSecret(role), nil
	}
	return c.urlSecret(), nil
}
