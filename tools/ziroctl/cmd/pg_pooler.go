package cmd

import (
	"fmt"
	"strconv"
	"time"
)

// The connection pooler: PgBouncer in front of a cluster, as a stateless two-replica cluster app (it holds
// no data, so the scheduler places and moves it freely). Clients connect to
// <name>-pool.cluster.ziro: database <db> goes to the read-write name, <db>_ro to the read-only one.
// Transaction pooling lets thousands of client connections share a few dozen server connections, which
// is what keeps max_connections (and the memory behind it) small. PgBouncer resolves the role-following
// names with a 5 s cache, so after a failover new server connections go to the new primary.
//
// The pooler gets its own secret with only what it needs: the application user's password and the TLS
// files. It connects to the members with sslmode=verify-ca and offers TLS to its clients.

// pgPoolerImage is PgBouncer, pinned by digest (Docker Hub, edoburu/pgbouncer v1.26.1-p0, multi-arch index).
const pgPoolerImage = "docker.io/edoburu/pgbouncer:v1.26.1-p0@sha256:488422e38cff912895d0d65d8963fcd306e6ac589a724398b6eb8e294e94d624"

// PGPooler is a cluster's pooler.
type PGPooler struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode"`            // transaction or session
	Size    int    `json:"size"`            // server connections per database and user
	Image   string `json:"image,omitempty"` // "" = pgPoolerImage
}

func (c *PGCluster) poolerApp() string    { return pgAppPrefix + c.Name + "-pool" }
func (c *PGCluster) poolerSecret() string { return pgSecretPrefix + c.Name + "-pool" }
func (c *PGCluster) poolerOn() bool       { return c.Pooler != nil && c.Pooler.Enabled }

func validPooler(p *PGPooler) error {
	if p.Mode != "transaction" && p.Mode != "session" {
		return fmt.Errorf("pool mode must be transaction or session")
	}
	if p.Size < 1 || p.Size > 500 {
		return fmt.Errorf("pool size must be 1-500")
	}
	return nil
}

// pgSetPooler turns the pooler on or off and changes its mode and size (zero values keep the current ones).
func pgSetPooler(st *ClusterState, name string, enable *bool, mode string, size int) error {
	c, err := pgCluster(st, name)
	if err != nil {
		return err
	}
	p := c.Pooler
	if p == nil {
		p = &PGPooler{Mode: "transaction", Size: 20}
	}
	next := *p
	if enable != nil {
		next.Enabled = *enable
	}
	if mode != "" {
		next.Mode = mode
	}
	if size > 0 {
		next.Size = size
	}
	if err := validPooler(&next); err != nil {
		return err
	}
	c.Pooler = &next
	return nil
}

// pgPoolerSecret keeps the pooler's secret in step with the cluster's (a password change, new certificates).
func pgPoolerSecret(st *ClusterState, c *PGCluster) {
	if !c.poolerOn() {
		delete(st.Secrets, c.poolerSecret())
		return
	}
	src := st.Secrets[c.secretName()]
	want := map[string]string{}
	for _, k := range []string{"POSTGRES_PASSWORD", "PG_TLS_CA", "PG_TLS_CERT", "PG_TLS_KEY"} {
		if v := src[k]; v != "" {
			want[k] = v
		}
	}
	cur := st.Secrets[c.poolerSecret()]
	same := len(cur) == len(want)
	for k, v := range want {
		same = same && cur[k] == v
	}
	if !same {
		st.Secrets[c.poolerSecret()] = want
	}
}

// pgPoolerApp is the pooler's cluster app.
func pgPoolerApp(st *ClusterState, c *PGCluster) ClusteredApp {
	p := c.Pooler
	image := p.Image
	if image == "" {
		image = pgPoolerImage
	}
	g := c.entryGroup()
	env := map[string]string{
		"POSTGRES_USER":     c.User,
		"POSTGRES_DB":       c.Database,
		"ZIRO_POOL_RW":      c.dnsRW(g) + "." + meshDomain,
		"ZIRO_POOL_RO":      c.dnsRO(g) + "." + meshDomain,
		"ZIRO_POOL_MODE":    p.Mode,
		"ZIRO_POOL_SIZE":    strconv.Itoa(p.Size),
		"ZIRO_POOL_CLIENTS": strconv.Itoa(max(1000, p.Size*50)),
	}
	if c.SecretEpoch > 0 {
		env["ZIRO_PG_SECRET_EPOCH"] = strconv.Itoa(c.SecretEpoch) // a new password: restart on it
	}
	return withPodNetwork(st, ClusteredApp{
		Name: c.poolerApp(), Image: image, Replicas: 2, Env: env, Args: []string{"sh", configMountPoint + "/pool.sh"},
		Secrets: []string{c.poolerSecret()}, AllowFrom: uniq(append([]string{}, c.AllowFrom...)), StopTimeout: 30,
		ConfigFiles: map[string]string{"pool.sh": pgPoolerScript},
	})
}

// pgEnsurePooler creates, updates or removes the pooler app; want records it as one of the cluster's apps.
func pgEnsurePooler(st *ClusterState, c *PGCluster, want map[string]bool, _ time.Time) {
	pgPoolerSecret(st, c)
	if !c.poolerOn() {
		return
	}
	want[c.poolerApp()] = true
	upsertApp(st, pgPoolerApp(st, c))
}

// pgPoolerIPs are the pod IPs of the running pooler replicas (behind <name>-pool).
func pgPoolerIPs(st *ClusterState, c *PGCluster) []string {
	var out []string
	for _, r := range st.Replicas {
		if r.App == c.poolerApp() && r.IP != "" && st.replicaRunning(r) {
			out = append(out, r.IP)
		}
	}
	return out
}

// pgPoolerScript is the pooler container's entry point (POSIX sh: the image is Alpine). It writes
// PgBouncer's configuration from the environment into a private directory and starts it.
const pgPoolerScript = `#!/bin/sh
# Ziro PgBouncer entry point (pg_pooler.go). The configuration comes from the environment; nothing here
# is taken from a client.
set -eu
umask 077
dir="${ZIRO_POOL_DIR:-/tmp/ziro-pgbouncer}"
mkdir -p "$dir"
tls_server="server_tls_sslmode = prefer"
tls_client=""
if [ -n "${PG_TLS_CERT:-}" ]; then
	printf %s "$PG_TLS_CA" | base64 -d >"$dir/ca.crt"
	printf %s "$PG_TLS_CERT" | base64 -d >"$dir/server.crt"
	printf %s "$PG_TLS_KEY" | base64 -d >"$dir/server.key"
	tls_server="server_tls_sslmode = verify-ca
server_tls_ca_file = $dir/ca.crt"
	tls_client="client_tls_sslmode = prefer
client_tls_cert_file = $dir/server.crt
client_tls_key_file = $dir/server.key
client_tls_ca_file = $dir/ca.crt"
fi
db="${POSTGRES_DB:?}"
cat >"$dir/pgbouncer.ini" <<EOF
[databases]
$db = host=${ZIRO_POOL_RW:?} port=5432 dbname=$db
${db}_ro = host=${ZIRO_POOL_RO:?} port=5432 dbname=$db

[pgbouncer]
listen_addr = *
listen_port = 5432
unix_socket_dir =
auth_type = scram-sha-256
auth_file = $dir/userlist.txt
pool_mode = ${ZIRO_POOL_MODE:-transaction}
default_pool_size = ${ZIRO_POOL_SIZE:-20}
max_client_conn = ${ZIRO_POOL_CLIENTS:-1000}
server_reset_query = DISCARD ALL
server_check_query = select 1
server_lifetime = 3600
server_idle_timeout = 60
dns_max_ttl = 5
ignore_startup_parameters = extra_float_digits,options
$tls_server
$tls_client
EOF
printf '"%s" "%s"\n' "${POSTGRES_USER:?}" "${POSTGRES_PASSWORD:?}" >"$dir/userlist.txt"
bin=$(command -v pgbouncer || echo /usr/bin/pgbouncer)
if [ "$(id -u)" = 0 ]; then
	# PgBouncer does not run as root: it drops to the image's postgres user.
	chown -R postgres "$dir" 2>/dev/null || true
	exec "$bin" -u postgres "$dir/pgbouncer.ini"
fi
exec "$bin" "$dir/pgbouncer.ini"
`
