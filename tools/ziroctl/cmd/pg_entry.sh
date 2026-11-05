#!/bin/bash
# Entry point of a Ziro Postgres member (RFC 0005, docs/postgres.md). It runs as root in the official
# postgres image and starts Postgres as the postgres user. The controller decides the role; this
# script only carries it out, and is safe to run again after any crash or restart:
#
#   - an empty data directory is initialised (primary) or copied from the primary with
#     pg_basebackup (replica), which never interrupts the primary;
#   - a member that is not the primary rewinds to the primary's timeline (pg_rewind, or a new base
#     backup) before it follows it;
#   - a member that believes it is primary but finds another live primary refuses to serve;
#   - a primary whose lease from the master ended stops acknowledging commits (the watchdog below), so
#     it never accepts writes next to a replica promoted in its place.
#
# Inputs: the environment (ZIRO_PG_*, PGDATA, passwords from the cluster secret) and the files in
# /etc/ziro-config: postgresql.conf (tuning), role and lease (key=value, kept current by the agent) and
# lease-until (when the lease ends, on this node's clock).
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

# STATE holds what must survive a wipe of PGDATA (it is the volume PGDATA lives in).
STATE="$(dirname "$PGDATA")"
BUILD="$STATE/ziro-building" # present while a base backup or rewind is under way: PGDATA is not to be trusted
STARTS="$STATE/ziro-starts"  # starts since this member last ran healthy for a minute
REBUILDS="$STATE/ziro-rebuilds" # base backups taken because the starts did not run healthy, since it last did
LASTERR="$STATE/ziro-last-error"
BUSY="$STATE/ziro-busy" # touched every 10 s while a copy runs: the agent reports it so a slow copy is not mistaken for a stuck member
BUSY_PID=

log() { echo "[ziro-pg] $*" >&2; }
as_pg() { gosu postgres "$@"; }
# fail MESSAGE: say why this start ends, where the agent and `ziroctl pg status` can read it.
fail() {
	log "$*"
	idle
	echo "$*" >"$LASTERR" 2>/dev/null || true
	exit 1
}
busy() {
	touch "$BUSY"
	(while :; do
		sleep 10
		touch "$BUSY"
	done) &
	BUSY_PID=$!
}
idle() {
	[ -n "$BUSY_PID" ] && kill "$BUSY_PID" 2>/dev/null
	BUSY_PID=
	rm -f "$BUSY"
}

role=replica
epoch=0
initialised=0
follow=
if [ -r "$CFG/role" ]; then
	while IFS='=' read -r key value; do
		case "$key" in
		role) role=$value ;;
		epoch) epoch=$value ;;
		initialised) initialised=$value ;;
		follow) follow=$value ;;
		esac
	done <"$CFG/role"
fi
case "$role" in primary | replica) ;; *) role=replica ;; esac
case "$follow" in *[!0-9a-z.-]* | '') follow= ;; esac

rw_host="${ZIRO_PG_RW:?}"
self_host="${ZIRO_PG_SELF:?}"
member="${ZIRO_PG_MEMBER:?}"
slot="ziro_${member}"
app_user="${POSTGRES_USER:?}"
app_db="${POSTGRES_DB:?}"

# TLS: the cluster CA, and this cluster's server certificate (pg_tls.go). Members connect to each other with
# sslmode=verify-ca: only a member of this cluster has a certificate its CA signed.
TLS="$STATE/ziro-tls"
tls=
sslmode=prefer
PGSSLROOTCERT=
if [ -n "${PG_TLS_CERT:-}" ] && [ -n "${PG_TLS_KEY:-}" ] && [ -n "${PG_TLS_CA:-}" ]; then
	mkdir -p "$TLS"
	printf %s "$PG_TLS_CA" | base64 -d >"$TLS/ca.crt"
	printf %s "$PG_TLS_CERT" | base64 -d >"$TLS/server.crt"
	printf %s "$PG_TLS_KEY" | base64 -d >"$TLS/server.key"
	chown -R postgres "$TLS"
	chmod 700 "$TLS"
	chmod 600 "$TLS/server.key"
	chmod 644 "$TLS/ca.crt" "$TLS/server.crt"
	tls=1
	sslmode=verify-ca
	PGSSLROOTCERT="$TLS/ca.crt"
fi
# Given to our own connections only (psql_at, pg_basebackup, pg_rewind): exported, the server would pass it
# on to every connection it makes (postgres_fdw, dblink).
PGSSLMODE="$sslmode"
export -n PGSSLMODE PGSSLROOTCERT 2>/dev/null || true

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
	PGCONNECT_TIMEOUT=3 as_pg env PGPASSFILE="$PGPASSFILE" PGSSLMODE="$PGSSLMODE" ${PGSSLROOTCERT:+PGSSLROOTCERT="$PGSSLROOTCERT"} psql -X -h "$host" -p "$PORT" -U replicator -d postgres "$@"
}

# serving_primary HOST: true when HOST accepts connections and is not in recovery.
serving_primary() { [ "$(psql_at "$1" -Atc 'select pg_is_in_recovery()' 2>/dev/null || true)" = f ]; }

# accepting HOST: true when HOST accepts connections (a replica to copy from need not be a primary).
accepting() { [ "$(psql_at "$1" -Atc 'select 1' 2>/dev/null || true)" = 1 ]; }

# wait_until CHECK HOST: poll CHECK HOST every 2 s (ZIRO_PG_WAIT_TRIES times, 120 = 4 minutes by default).
wait_until() {
	local check=$1 host=$2 i
	for i in $(seq 1 "${ZIRO_PG_WAIT_TRIES:-120}"); do
		if "$check" "$host"; then return 0; fi
		sleep 2
	done
	return 1
}
wait_for_primary() { wait_until serving_primary "$1"; }

# why_not HOST: in one line, why HOST cannot be copied: psql's own reason (a refused connection, a wrong
# password, a certificate that does not match) or that it answers but is not a primary. "No primary" alone
# hides which of these it is, and the fix is different for each.
why_not() {
	local err
	# psql prints the error on its first line and a hint ("Is the server running ...") after it.
	err=$(psql_at "$1" -Atc 'select pg_is_in_recovery()' 2>&1 >/dev/null | head -n 1 | tr -d '\r' | sed 's/^psql: error: //' | cut -c1-160) || true
	echo "${err:-it answers but is not a primary}"
}

# hot_standby_floor prints the settings a hot standby must not have lower than its primary: Postgres refuses to start
# a replica whose max_connections, max_worker_processes, max_wal_senders, max_prepared_transactions or
# max_locks_per_transaction are below the primary's (it checks against the control file the copy brought). A
# replica restarts before its primary when a new spec rolls out and when the limits shrink, so it asks the
# primary for its values and keeps the higher of the two: the primary then restarts with its own, lower ones,
# which a replica with higher ones may keep. Without a primary to ask, the configured values stand.
hot_standby_floor() {
	local rows name value mine
	rows=$(psql_at "$rw_host" -Atc "select name || '=' || setting from pg_settings where name in ('max_connections','max_worker_processes','max_wal_senders','max_prepared_transactions','max_locks_per_transaction')" 2>/dev/null) || return 0
	while IFS='=' read -r name value; do
		case "$name" in max_connections | max_worker_processes | max_wal_senders | max_prepared_transactions | max_locks_per_transaction) ;; *) continue ;; esac
		case "$value" in '' | *[!0-9]*) continue ;; esac
		mine=$(sed -n "s/^$name = \([0-9][0-9]*\)\$/\1/p" "$CFG/postgresql.conf" | tail -n 1)
		if [ -z "$mine" ] || [ "$value" -gt "$mine" ]; then
			echo "$name = $value"
			log "raising $name to the primary's $value (configured: ${mine:-the default}): a replica may not have less" >&2
		fi
	done <<<"$rows"
}

# Backups (pg_backup.go): pgBackRest's logs, archive spool and locks live on the data volume.
stanza="${ZIRO_PG_STANZA:-}"
case "$stanza" in *[!a-z0-9]*) stanza= ;; esac
if [ -n "$stanza" ]; then
	mkdir -p "$STATE/ziro-pgbackrest/log" "$STATE/ziro-pgbackrest/spool" "$STATE/ziro-pgbackrest/lock"
	chown -R postgres "$STATE/ziro-pgbackrest"
fi

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

# restore_primary: the first primary of a cluster made from a backup repository (pg restore) takes its
# data from there: the latest state, or the state at ZIRO_PG_RESTORE_TARGET. Postgres then replays the
# archived WAL and becomes the primary on a new timeline.
restore_primary() {
	local path=${ZIRO_PG_RESTORE_PATH:?} rstanza=${ZIRO_PG_RESTORE_STANZA:?} target=${ZIRO_PG_RESTORE_TARGET:-}
	log "restoring from the backup repository ($path, stanza $rstanza, ${target:-the latest state})"
	touch "$BUILD"
	busy
	rm -rf "${PGDATA:?}"/* "${PGDATA:?}"/.[!.]* 2>/dev/null || true
	as_pg mkdir -p "$PGDATA"
	set -- --stanza="$rstanza" --repo1-path="$path" --pg1-path="$PGDATA"
	if [ -n "$target" ]; then
		set -- "$@" --type=time --target="$target" --target-action=promote
	fi
	if ! as_pg pgbackrest "$@" restore; then
		fail "the restore from the backup repository failed (see the container log)"
	fi
	idle
	rm -f "$BUILD"
}

# basebackup HOST: a fresh copy of the primary. The slot keeps the WAL the copy needs until it
# connects. Nothing is written to the primary besides the slot, and its clients are not affected.
basebackup() {
	local host=$1 slot_args="-C -S $slot"
	log "taking a base backup from $host"
	if [ "$host" = "$rw_host" ]; then
		wait_for_primary "$host" || fail "no primary at $host: $(why_not "$host")"
	else
		# Another replica was named as the source, to spare the primary (pg add-replica --from). It has no slot
		# of ours to create: the primary does, and it must exist before the copy so the WAL since then is kept
		# (the controller creates the slots of a group once per epoch, which is too late for a new member).
		wait_for_primary "$rw_host" || fail "no primary at $rw_host: $(why_not "$rw_host")"
		psql_at "$rw_host" -Atc "select pg_create_physical_replication_slot('$slot', true) where not exists (select from pg_replication_slots where slot_name = '$slot')" >/dev/null 2>&1 ||
			fail "cannot create the replication slot $slot on $rw_host"
		wait_until accepting "$host" || fail "cannot copy from $host: $(why_not "$host")"
		slot_args=
	fi
	# The marker goes down before anything is deleted and comes up only when the copy is whole: a copy
	# that dies half way leaves a PG_VERSION behind, and without the marker the next start would run
	# Postgres on it for ever.
	touch "$BUILD"
	busy
	rm -rf "${PGDATA:?}"/* "${PGDATA:?}"/.[!.]* 2>/dev/null || true
	as_pg mkdir -p "$PGDATA"
	if [ -n "$slot_args" ]; then # the copy creates its slot on the primary: an old one that nothing uses is dropped first
		psql_at "$host" -Atc "select pg_drop_replication_slot('$slot') from pg_replication_slots where slot_name = '$slot' and not active" >/dev/null 2>&1 || true
	fi
	# shellcheck disable=SC2086 # slot_args is two words or none
	if ! as_pg env PGPASSFILE="$PGPASSFILE" PGSSLMODE="$PGSSLMODE" ${PGSSLROOTCERT:+PGSSLROOTCERT="$PGSSLROOTCERT"} pg_basebackup -h "$host" -p "$PORT" -U replicator -D "$PGDATA" \
		-X stream $slot_args --checkpoint=fast --no-password; then
		fail "pg_basebackup from $host failed (see the container log)"
	fi
	idle
	rm -f "$BUILD"
}

# rejoin: this data directory was a primary (or diverged); make it follow the current primary.
rejoin() {
	log "rejoining the primary at $rw_host"
	if ! wait_for_primary "$rw_host"; then
		fail "no primary at $rw_host yet: $(why_not "$rw_host")"
	fi
	touch "$BUILD"
	busy
	if as_pg env PGPASSFILE="$PGPASSFILE" PGSSLMODE="$PGSSLMODE" ${PGSSLROOTCERT:+PGSSLROOTCERT="$PGSSLROOTCERT"} pg_rewind --target-pgdata="$PGDATA" \
		--source-server="host=$rw_host port=$PORT user=replicator dbname=postgres" >&2; then
		idle
		rm -f "$BUILD"
		log "rewound to the primary's timeline"
	else
		idle
		log "pg_rewind failed; copying the primary"
		basebackup "$rw_host"
	fi
}

# Where a new data directory is copied from. A replica added with --from takes its first copy from the member it
# names; a rebuild always copies the primary, whatever this container was created with: the environment is fixed
# when the container is created, and the controller cannot change it for the restart that a rebuild causes.
copy_from="${ZIRO_PG_FROM:-$rw_host}"

# A rebuild was requested (ziroctl pg reinit): throw this data directory away and take a new base
# backup. Only a replica does; a member that is the primary now ignores the request.
if [ -f "$PGDATA/ziro-reinit" ]; then
	rm -f "$PGDATA/ziro-reinit"
	if [ "$role" = replica ]; then
		log "rebuild requested: discarding this data directory"
		rm -f "$PGDATA/PG_VERSION"
		copy_from="$rw_host"
	else
		log "rebuild requested, but this member is the primary: ignored"
	fi
fi

# A copy or rewind that did not finish: whatever is in PGDATA is not a database.
if [ -f "$BUILD" ]; then
	log "an earlier base backup or rewind did not finish: discarding this data directory"
	rm -f "$PGDATA/PG_VERSION"
fi

# A replica that has started over and over without once running healthy has data it cannot use (a
# lost WAL segment, a timeline that is not a child of the primary's): copy the primary again. Only while
# a primary answers, so the copy being thrown away is never the only one.
starts=$(cat "$STARTS" 2>/dev/null || echo 0)
case "$starts" in '' | *[!0-9]*) starts=0 ;; esac
starts=$((starts + 1))
if [ "$starts" -gt "${ZIRO_PG_MAX_STARTS:-4}" ] && [ "$role" = replica ] && [ -f "$PGDATA/PG_VERSION" ]; then
	if serving_primary "$rw_host"; then
		# Copies that do not mend it come ever more slowly: a member that cannot run on a fresh copy has a
		# problem the copy does not touch (its node, its disk, its configuration), and copying the primary
		# over and over only loads the primary and the network. The first is at once, then 1, 2, 3 ... minutes.
		rebuilds=$(cat "$REBUILDS" 2>/dev/null || echo 0)
		case "$rebuilds" in '' | *[!0-9]*) rebuilds=0 ;; esac
		rebuilds=$((rebuilds + 1))
		echo "$rebuilds" >"$REBUILDS"
		if [ "$rebuilds" -gt 1 ]; then
			pause=$(((rebuilds - 1) * ${ZIRO_PG_REBUILD_BACKOFF:-60}))
			[ "$pause" -le 600 ] || pause=600
			log "$((starts - 1)) starts in a row did not run healthy, and $((rebuilds - 1)) copies before did not help: waiting ${pause}s before copying the primary again"
			echo "copied ${rebuilds} times without running healthy: the copy is not the problem (see the container log); waiting ${pause}s" >"$LASTERR" 2>/dev/null || true
			sleep "$pause"
		fi
		log "$((starts - 1)) starts in a row did not run healthy: taking a new base backup"
		rm -f "$PGDATA/PG_VERSION"
		copy_from="$rw_host"
		starts=1
	else
		log "$((starts - 1)) starts in a row did not run healthy, but no primary answers: keeping the data directory"
	fi
fi
echo "$starts" >"$STARTS"

if [ ! -f "$PGDATA/PG_VERSION" ]; then
	if [ "${ZIRO_PG_INIT:-replica}" = restore ] && [ "$role" = primary ] && [ "$initialised" != 1 ]; then
		restore_primary
	elif [ "${ZIRO_PG_INIT:-replica}" = primary ] && [ "$role" = primary ]; then
		if [ "$initialised" = 1 ]; then
			# This member served a database before: an empty data directory is a loss, and a new empty
			# database here would silently replace it. Stay down so the controller fails over to a replica.
			fail "the data directory is empty but this member already served a database: refusing to create a new one"
		fi
		init_primary
	else
		basebackup "$copy_from"
		as_pg touch "$PGDATA/standby.signal"
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
	as_pg touch "$PGDATA/standby.signal"
fi

# Settings. ziro.conf is rewritten on every start; the controller changes the rest (the synchronous
# standbys, read-only fencing) with ALTER SYSTEM, which lands in postgresql.auto.conf.
# The primary to follow: the member the controller names (role file), else the read-write name.
conninfo="host=${follow:-$rw_host} port=$PORT user=replicator application_name=$member"
[ -n "$tls" ] && conninfo="$conninfo sslmode=verify-ca sslrootcert=$TLS/ca.crt"
{
	cat "$CFG/postgresql.conf"
	if [ "$role" = replica ]; then hot_standby_floor; fi
	echo "primary_conninfo = '$conninfo'"
	echo "primary_slot_name = '$slot'"
	if [ -n "$tls" ]; then
		echo "ssl = on"
		echo "ssl_cert_file = '$TLS/server.crt'"
		echo "ssl_key_file = '$TLS/server.key'"
		echo "ssl_ca_file = '$TLS/ca.crt'"
		echo "ssl_min_protocol_version = 'TLSv1.2'"
	fi
	if [ -n "${ZIRO_PG_CITUS:-}" ]; then
		echo "shared_preload_libraries = 'citus,pg_stat_statements,auto_explain'" # Citus first, as it requires
		if [ -n "$tls" ]; then
			echo "citus.node_conninfo = 'sslmode=verify-ca sslrootcert=$TLS/ca.crt'"
		else
			echo "citus.node_conninfo = 'sslmode=prefer'"
		fi
	fi
	if [ -n "$stanza" ]; then
		# WAL goes to the repository as it is written (asynchronously, through the spool), at least once a
		# minute while there are writes; a replica whose slot no longer has a segment fetches it from there.
		echo "archive_mode = on"
		echo "archive_command = 'pgbackrest --stanza=$stanza archive-push %p'"
		echo "archive_timeout = 60"
		echo "restore_command = 'pgbackrest --stanza=$stanza archive-get %f \"%p\"'"
	fi
	# The parameters set with ziroctl pg set that a reload applies (kept current by the agent).
	echo "include_if_exists = '$CFG/params.conf'"
} >"$PGDATA/ziro.conf"
grep -q "^include_if_exists = 'ziro.conf'" "$PGDATA/postgresql.conf" || echo "include_if_exists = 'ziro.conf'" >>"$PGDATA/postgresql.conf"
if [ -f "$PGDATA/postgresql.auto.conf" ]; then
	# The controller's primary_conninfo (opFollow) is for the running server; a start takes it from the role file.
	sed -i '/^primary_conninfo/d' "$PGDATA/postgresql.auto.conf"
	if [ ! -f "$PGDATA/recovery.signal" ]; then
		# A restore's settings (pgBackRest writes them here) are for that one recovery: left in place, a
		# later standby would stop replaying at the old target and fetch WAL from the source repository.
		sed -i '/^restore_command/d; /^recovery_target/d' "$PGDATA/postgresql.auto.conf"
	fi
	if [ "$role" = replica ]; then
		sed -i '/^default_transaction_read_only/d' "$PGDATA/postgresql.auto.conf"
	fi
fi
# The superuser connects over the local socket only (the agent uses it); Citus nodes connect to each
# other as the superuser, with TLS when the cluster has it. Replication uses its own role.
host=host
[ -n "$tls" ] && host=hostssl
{
	echo "local all all trust"
	echo "$host replication replicator ${ZIRO_PG_NET:?} scram-sha-256"
	if [ -n "${ZIRO_PG_CITUS:-}" ]; then
		echo "$host all postgres ${ZIRO_PG_NET} scram-sha-256"
	else
		echo "host all postgres ${ZIRO_PG_NET} reject"
	fi
	echo "host all all ${ZIRO_PG_NET} scram-sha-256"
} >"$PGDATA/pg_hba.conf"
chown postgres "$PGDATA/ziro.conf" "$PGDATA/pg_hba.conf" "$PGDATA/postgresql.conf"
[ -f "$PGDATA/postgresql.auto.conf" ] && chown postgres "$PGDATA/postgresql.auto.conf"
# The server reads standby.signal only to know it exists, but a base backup taken from this replica (pg add-replica
# --from) streams it like every other file, and a root-owned 0600 file (this script's umask) stops that copy.
[ -f "$PGDATA/standby.signal" ] && chown postgres "$PGDATA/standby.signal"

# ---- accounts, once the primary accepts connections ----

if [ "$role" = primary ]; then
	(
		server=$$
		until as_pg psql -X -h "$SOCK" -p "$PORT" -d postgres -Atc 'select 1' >/dev/null 2>&1; do sleep 1; done
		# A restored primary replays the archive first; the accounts are set once it has finished.
		until [ "$(as_pg psql -X -h "$SOCK" -p "$PORT" -d postgres -Atc 'select pg_is_in_recovery()' 2>/dev/null || true)" = f ]; do
			kill -0 "$server" 2>/dev/null || exit 0
			sleep 2
		done
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

# Healthy means: a primary, or a replica whose receiver is streaming, for a minute. Then the start
# count and the last error are forgotten.
(
	until [ "$(as_pg psql -X -h "$SOCK" -p "$PORT" -d postgres -Atc "select (not pg_is_in_recovery()) or exists (select from pg_stat_wal_receiver where status = 'streaming')" 2>/dev/null || true)" = t ]; do sleep 2; done
	sleep 60
	if [ "$(as_pg psql -X -h "$SOCK" -p "$PORT" -d postgres -Atc "select (not pg_is_in_recovery()) or exists (select from pg_stat_wal_receiver where status = 'streaming')" 2>/dev/null || true)" = t ]; then
		echo 0 >"$STARTS"
		rm -f "$LASTERR" "$REBUILDS"
	fi
) &

# ---- the lease watchdog (pg_lease.go) ----

LEASE_UNTIL="$CFG/lease-until"
LEASE_SEEN="$STATE/ziro-lease-seen" # this member has had a lease: from now on a missing one counts as ended
FENCED="$STATE/ziro-lease-fence"    # present while fenced; holds the standby list the fence replaced
FENCE_NAME=ziro_fenced

lease_enforced() { grep -qx 'fence=1' "$CFG/lease" 2>/dev/null; }
lease_valid() {
	local until=0
	[ -r "$LEASE_UNTIL" ] && read -r until _ <"$LEASE_UNTIL" 2>/dev/null
	case "$until" in '' | *[!0-9]*) until=0 ;; esac
	[ "$(date +%s)" -lt "$until" ]
}
q() { as_pg psql -X -h "$SOCK" -p "$PORT" -d postgres -Atc "$1" 2>/dev/null; }
fence() {
	local cur
	cur=$(q "select current_setting('synchronous_standby_names')") || return 0
	[ -f "$FENCED" ] || printf '%s' "$cur" >"$FENCED"
	[ "$cur" = "$FENCE_NAME" ] && return 0
	q "alter system set synchronous_standby_names = '$FENCE_NAME'" >/dev/null &&
		q "select pg_reload_conf()" >/dev/null &&
		q "select pg_terminate_backend(pid) from pg_stat_activity where backend_type = 'client backend' and pid <> pg_backend_pid()" >/dev/null &&
		log "the lease from the master ended: commits are no longer acknowledged until it is renewed"
}
unfence() {
	local saved cur
	saved=$(cat "$FENCED" 2>/dev/null || true)
	cur=$(q "select current_setting('synchronous_standby_names')") || return 0
	if [ "$cur" = "$FENCE_NAME" ] && [ "$saved" != "$FENCE_NAME" ]; then
		if [ -z "$saved" ]; then
			q "alter system reset synchronous_standby_names" >/dev/null || return 0
		elif printf '%s' "$saved" | grep -Eqx 'ANY [12] \(m[0-9]{1,3}(, m[0-9]{1,3})*\)'; then
			q "alter system set synchronous_standby_names = '$saved'" >/dev/null || return 0
		else
			return 0
		fi
		q "select pg_reload_conf()" >/dev/null
		log "the lease was renewed: commits are acknowledged again"
	fi
	rm -f "$FENCED"
}
watchdog() {
	local server=$$ # this shell's pid, which becomes the server's with the exec below
	while :; do
		sleep 1
		kill -0 "$server" 2>/dev/null || exit 0 # the server is gone: so is the reason to watch
		if ! lease_enforced; then
			[ -f "$FENCED" ] && unfence
			continue
		fi
		[ -f "$LEASE_UNTIL" ] && [ ! -f "$LEASE_SEEN" ] && touch "$LEASE_SEEN"
		[ -f "$LEASE_SEEN" ] || continue
		[ "$(q 'select pg_is_in_recovery()')" = f ] || continue
		if lease_valid; then
			[ -f "$FENCED" ] && unfence
		else
			fence
		fi
	done
}

# A primary that restarts without a lease (it had one before) starts fenced, so not even its first
# seconds accept a commit the master does not know about.
if [ "$role" = primary ] && lease_enforced && [ -f "$LEASE_SEEN" ] && ! lease_valid && [ -f "$PGDATA/postgresql.auto.conf" ]; then
	cur=$(sed -n "s/^synchronous_standby_names = '\(.*\)'\$/\1/p" "$PGDATA/postgresql.auto.conf" | tail -n 1)
	[ -f "$FENCED" ] || printf '%s' "$cur" >"$FENCED"
	sed -i '/^synchronous_standby_names/d' "$PGDATA/postgresql.auto.conf"
	echo "synchronous_standby_names = '$FENCE_NAME'" >>"$PGDATA/postgresql.auto.conf"
	log "no lease from the master: starting fenced"
fi
watchdog &

log "starting as $role (epoch $epoch)"
exec gosu postgres postgres -D "$PGDATA" -c "listen_addresses=$LISTEN" -c "port=$PORT" -c "unix_socket_directories=$SOCK" \
	-c "config_file=$PGDATA/postgresql.conf" -c "hba_file=$PGDATA/pg_hba.conf"
