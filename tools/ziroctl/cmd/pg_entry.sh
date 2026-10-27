#!/bin/bash
# Entry point of a Ziro Postgres member (RFC 0005, docs/postgres.md). It runs as root in the official
# postgres image and starts Postgres as the postgres user. The controller decides the role; this
# script only carries it out, and is safe to run again after any crash or restart:
#
#   - an empty data directory is initialised (primary) or copied from the primary with
#     pg_basebackup (replica), which never interrupts the primary;
#   - a member that is not the primary rewinds to the primary's timeline (pg_rewind, or a new base
#     backup) before it follows it;
#   - a member that believes it is primary but finds another live primary refuses to serve.
#
# Inputs: the environment (ZIRO_PG_*, PGDATA, passwords from the cluster secret) and the files in
# /etc/ziro-config: postgresql.conf (tuning) and role (key=value, written by the agent).
set -eu
umask 077

# The defaults are the container's; tests (tests/pg/entry-test.sh) point them elsewhere.
CFG="${ZIRO_PG_CONFIG_DIR:-/etc/ziro-config}"
PORT="${ZIRO_PG_PORT:-5432}"
SOCK="${ZIRO_PG_SOCKET_DIR:-/var/run/postgresql}"
LISTEN="${ZIRO_PG_LISTEN:-*}"
export PATH="$PATH:/usr/lib/postgresql/${PG_MAJOR:-17}/bin"
export PGDATA="${PGDATA:?PGDATA is not set}"
PGPASSFILE="${ZIRO_PG_PASSFILE:-/tmp/.ziro-pgpass}"
export PGPASSFILE

log() { echo "[ziro-pg] $*" >&2; }
as_pg() { gosu postgres "$@"; }

role=replica
epoch=0
initialised=0
if [ -r "$CFG/role" ]; then
	while IFS='=' read -r key value; do
		case "$key" in
		role) role=$value ;;
		epoch) epoch=$value ;;
		initialised) initialised=$value ;;
		esac
	done <"$CFG/role"
fi
case "$role" in primary | replica) ;; *) role=replica ;; esac

rw_host="${ZIRO_PG_RW:?}"
self_host="${ZIRO_PG_SELF:?}"
member="${ZIRO_PG_MEMBER:?}"
slot="ziro_${member}"
app_user="${POSTGRES_USER:?}"
app_db="${POSTGRES_DB:?}"

# Passwords for connections between members (and, with Citus, between nodes).
{
	printf '*:*:*:replicator:%s\n' "${PG_REPL_PASSWORD:?}"
	printf '*:*:*:postgres:%s\n' "${PG_SUPERUSER_PASSWORD:?}"
	printf '*:*:*:%s:%s\n' "$app_user" "${POSTGRES_PASSWORD:?}"
} >"$PGPASSFILE"
chown postgres "$PGPASSFILE"
chmod 600 "$PGPASSFILE"

ip_of() { getent hosts "$1" | awk '{print $1; exit}'; }

# psql_at HOST ARGS...: a quick connection to another member as the replication user.
psql_at() {
	local host=$1
	shift
	PGCONNECT_TIMEOUT=3 as_pg env PGPASSFILE="$PGPASSFILE" psql -X -h "$host" -p "$PORT" -U replicator -d postgres "$@"
}

# serving_primary HOST: true when HOST accepts connections and is not in recovery.
serving_primary() { [ "$(psql_at "$1" -Atc 'select pg_is_in_recovery()' 2>/dev/null || true)" = f ]; }

wait_for_primary() {
	local host=$1 i
	for i in $(seq 1 120); do
		if serving_primary "$host"; then return 0; fi
		sleep 2
	done
	return 1
}

# ---- first start ----

init_primary() {
	log "initialising a new database"
	local pwfile
	pwfile=$(mktemp)
	printf %s "$PG_SUPERUSER_PASSWORD" >"$pwfile"
	chown postgres "$pwfile"
	as_pg mkdir -p "$PGDATA"
	as_pg initdb -D "$PGDATA" -U postgres --pwfile="$pwfile" --data-checksums \
		--auth-local=trust --auth-host=scram-sha-256 --encoding=UTF8
	rm -f "$pwfile"
}

# basebackup HOST: a fresh copy of the primary. The slot keeps the WAL the copy needs until it
# connects. Nothing is written to the primary besides the slot, and its clients are not affected.
basebackup() {
	local host=$1
	log "taking a base backup from $host"
	if ! wait_for_primary "$host"; then
		log "no primary at $host"
		exit 1
	fi
	rm -rf "${PGDATA:?}"/* "${PGDATA:?}"/.[!.]* 2>/dev/null || true
	as_pg mkdir -p "$PGDATA"
	psql_at "$host" -Atc "select pg_drop_replication_slot('$slot') from pg_replication_slots where slot_name = '$slot' and not active" >/dev/null 2>&1 || true
	as_pg env PGPASSFILE="$PGPASSFILE" pg_basebackup -h "$host" -p "$PORT" -U replicator -D "$PGDATA" \
		-X stream -C -S "$slot" --checkpoint=fast --no-password
}

# rejoin: this data directory was a primary (or diverged); make it follow the current primary.
rejoin() {
	log "rejoining the primary at $rw_host"
	if ! wait_for_primary "$rw_host"; then
		log "no primary at $rw_host yet"
		exit 1
	fi
	if as_pg env PGPASSFILE="$PGPASSFILE" pg_rewind --target-pgdata="$PGDATA" \
		--source-server="host=$rw_host port=$PORT user=replicator dbname=postgres" >&2; then
		log "rewound to the primary's timeline"
	else
		log "pg_rewind failed; copying the primary"
		basebackup "$rw_host"
	fi
}

# A rebuild was requested (ziroctl pg reinit): throw this data directory away and take a new base
# backup. Only a replica does; a member that is the primary now ignores the request.
if [ -f "$PGDATA/ziro-reinit" ]; then
	rm -f "$PGDATA/ziro-reinit"
	if [ "$role" = replica ]; then
		log "rebuild requested: discarding this data directory"
		rm -f "$PGDATA/PG_VERSION"
	else
		log "rebuild requested, but this member is the primary: ignored"
	fi
fi

if [ ! -f "$PGDATA/PG_VERSION" ]; then
	if [ "${ZIRO_PG_INIT:-replica}" = primary ] && [ "$role" = primary ]; then
		if [ "$initialised" = 1 ]; then
			# This member served a database before: an empty data directory is a loss, and a new empty
			# database here would silently replace it. Stay down so the controller fails over to a replica.
			log "the data directory is empty but this member already served a database: refusing to create a new one"
			exit 1
		fi
		init_primary
	else
		basebackup "${ZIRO_PG_FROM:-$rw_host}"
		touch "$PGDATA/standby.signal"
	fi
fi

# ---- every start ----

# Another live primary means this member was replaced while it was away.
if [ "$role" = primary ] && [ ! -f "$PGDATA/standby.signal" ]; then
	rw_ip=$(ip_of "$rw_host" || true)
	my_ip=$(ip_of "$self_host" || true)
	if [ -n "$rw_ip" ] && [ "$rw_ip" != "$my_ip" ] && serving_primary "$rw_ip"; then
		log "$rw_host is served by another primary: not starting as primary"
		role=replica
	fi
fi
if [ "$role" = replica ] && [ ! -f "$PGDATA/standby.signal" ]; then
	rejoin
fi
if [ "$role" = replica ]; then
	touch "$PGDATA/standby.signal"
fi

# Settings. ziro.conf is rewritten on every start; the controller changes the rest (the synchronous
# standbys, read-only fencing) with ALTER SYSTEM, which lands in postgresql.auto.conf.
{
	cat "$CFG/postgresql.conf"
	echo "primary_conninfo = 'host=$rw_host port=$PORT user=replicator application_name=$member'"
	echo "primary_slot_name = '$slot'"
	if [ -n "${ZIRO_PG_CITUS:-}" ]; then
		echo "shared_preload_libraries = 'citus'"
		echo "citus.node_conninfo = 'sslmode=prefer'"
	fi
} >"$PGDATA/ziro.conf"
grep -q "^include_if_exists = 'ziro.conf'" "$PGDATA/postgresql.conf" || echo "include_if_exists = 'ziro.conf'" >>"$PGDATA/postgresql.conf"
if [ "$role" = replica ] && [ -f "$PGDATA/postgresql.auto.conf" ]; then
	sed -i '/^default_transaction_read_only/d' "$PGDATA/postgresql.auto.conf"
fi
cat >"$PGDATA/pg_hba.conf" <<EOF
local all all trust
host replication replicator ${ZIRO_PG_NET:?} scram-sha-256
host all all ${ZIRO_PG_NET} scram-sha-256
EOF
chown postgres "$PGDATA/ziro.conf" "$PGDATA/pg_hba.conf" "$PGDATA/postgresql.conf"
[ -f "$PGDATA/postgresql.auto.conf" ] && chown postgres "$PGDATA/postgresql.auto.conf"

# ---- accounts, once the primary accepts connections ----

if [ "$role" = primary ]; then
	(
		until as_pg psql -X -h "$SOCK" -p "$PORT" -d postgres -Atc 'select 1' >/dev/null 2>&1; do sleep 1; done
		[ "$(as_pg psql -X -h "$SOCK" -p "$PORT" -d postgres -Atc 'select pg_is_in_recovery()')" = f ] || exit 0
		as_pg psql -X -h "$SOCK" -p "$PORT" -d postgres -v ON_ERROR_STOP=1 \
			-v repl="$PG_REPL_PASSWORD" -v app_user="$app_user" -v app_pass="$POSTGRES_PASSWORD" -v app_db="$app_db" <<'SQL'
SELECT format('CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD %L', :'repl')
  WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'replicator') \gexec
SELECT format('ALTER ROLE replicator WITH PASSWORD %L', :'repl') \gexec
GRANT EXECUTE ON FUNCTION pg_ls_dir(text, boolean, boolean), pg_stat_file(text, boolean),
  pg_read_binary_file(text), pg_read_binary_file(text, bigint, bigint, boolean) TO replicator;
SELECT format('CREATE ROLE %I WITH LOGIN PASSWORD %L', :'app_user', :'app_pass')
  WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'app_user') \gexec
SELECT format('ALTER ROLE %I WITH PASSWORD %L', :'app_user', :'app_pass') \gexec
SELECT format('CREATE DATABASE %I OWNER %I', :'app_db', :'app_user')
  WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'app_db') \gexec
SQL
		if [ -n "${ZIRO_PG_CITUS:-}" ]; then
			as_pg psql -X -h "$SOCK" -p "$PORT" -d "$app_db" -v ON_ERROR_STOP=1 -c 'CREATE EXTENSION IF NOT EXISTS citus' >/dev/null
		fi
		log "accounts are in place"
	) &
fi

log "starting as $role (epoch $epoch)"
exec gosu postgres postgres -D "$PGDATA" -c "listen_addresses=$LISTEN" -c "port=$PORT" -c "unix_socket_directories=$SOCK" \
	-c "config_file=$PGDATA/postgresql.conf" -c "hba_file=$PGDATA/pg_hba.conf"
