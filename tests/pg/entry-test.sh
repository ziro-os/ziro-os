#!/bin/bash
# Runs the Postgres member entry script (tools/ziroctl/cmd/pg_entry.sh) against real PostgreSQL
# binaries, outside a container: a primary, a replica taken with pg_basebackup, a promotion, and the
# old primary rejoining by pg_rewind (clean stop) or a new base backup (crash), including the refusal
# to start as primary when another primary is serving. It needs root (it plays the container), the
# PostgreSQL server binaries and util-linux's runuser, and it edits /etc/hosts for the test names
# (removed on exit). Usage: tests/pg/entry-test.sh   (exit 0 = pass, 77 = skipped).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
entry="$here/../../tools/ziroctl/cmd/pg_entry.sh"

[ "$(id -u)" = 0 ] || { echo "skip: needs root"; exit 77; }
bindir=$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1 || true)
[ -n "$bindir" ] && [ -x "$bindir/initdb" ] || { echo "skip: no PostgreSQL server binaries"; exit 77; }
command -v runuser >/dev/null || { echo "skip: no runuser"; exit 77; }
id postgres >/dev/null 2>&1 || { echo "skip: no postgres user"; exit 77; }
major=$(basename "$(dirname "$bindir")")

work=$(mktemp -d /tmp/ziro-pg-test.XXXXXX)
chmod 755 "$work"
mkdir "$work/bin"
cat >"$work/bin/gosu" <<'SH'
#!/bin/sh
user=$1
shift
exec runuser -u "$user" -- "$@"
SH
chmod +x "$work/bin/gosu"
export PATH="$work/bin:$bindir:$PATH"

ip1=127.0.0.11 ip2=127.0.0.12
hosts_mark="# ziro-pg-test $$"
# Rewrites /etc/hosts in place (a bind mount in a container cannot be replaced by a rename, as sed -i does).
hosts_del() { # hosts_del PATTERN: drop the matching lines
	local tmp
	tmp=$(mktemp)
	grep -v -- "$1" /etc/hosts >"$tmp" || true
	cat "$tmp" >/etc/hosts
	rm -f "$tmp"
}
set_rw() { # set_rw IP: point the read-write name at a member
	hosts_del "ziro-pg-test-rw"
	echo "$1 rw.pgtest # ziro-pg-test-rw $hosts_mark" >>/etc/hosts
}
{
	echo "$ip1 m1.pgtest $hosts_mark"
	echo "$ip2 m2.pgtest $hosts_mark"
} >>/etc/hosts

cleanup() {
	for f in "$work"/*/pid; do
		[ -f "$f" ] && pkill -9 -P "$(cat "$f")" 2>/dev/null || true
		[ -f "$f" ] && kill -9 "$(cat "$f")" 2>/dev/null || true
	done
	pkill -9 -u postgres -f "$work" 2>/dev/null || true
	hosts_del "$hosts_mark"
	[ -n "${KEEP:-}" ] || rm -rf "$work"
}
trap cleanup EXIT

pass=0
fail() { echo "FAIL: $*"; for l in "$work"/*/log; do echo "--- $l"; grep -h 'ziro-pg' "$l" | tail -n 15; tail -n 12 "$l"; done; exit 1; }
ok() { pass=$((pass + 1)); echo "ok: $*"; }

# member NAME IP: create the directories of a member
member() {
	local d="$work/$1"
	mkdir -p "$d/cfg" "$d/data" "$d/sock"
	chown -R postgres "$d/data" "$d/sock"
	chmod 755 "$d" "$d/cfg"
	printf 'shared_buffers = 32MB\nwal_level = replica\nwal_log_hints = on\nmax_wal_senders = 10\nmax_replication_slots = 10\nhot_standby = on\nrecovery_target_timeline = latest\n' >"$d/cfg/postgresql.conf"
}
role() { printf 'role=%s\nepoch=%s\n' "$2" "${3:-0}" >"$work/$1/cfg/role"; }

# start NAME IP INIT: run the entry script as the container would
start() {
	local n=$1 ip=$2 init=$3 d="$work/$1"
	env ZIRO_PG_CONFIG_DIR="$d/cfg" ZIRO_PG_PORT=5499 ZIRO_PG_SOCKET_DIR="$d/sock" ZIRO_PG_LISTEN="$ip" \
		ZIRO_PG_PASSFILE="$d/pgpass" PG_MAJOR="$major" PGDATA="$d/data/pgdata" \
		ZIRO_PG_RW=rw.pgtest ZIRO_PG_SELF="$n.pgtest" ZIRO_PG_MEMBER="$n" ZIRO_PG_INIT="$init" ZIRO_PG_NET=127.0.0.0/8 \
		POSTGRES_USER=app POSTGRES_DB=appdb POSTGRES_PASSWORD=apppass PG_REPL_PASSWORD=replpass PG_SUPERUSER_PASSWORD=superpass \
		bash "$entry" >>"$d/log" 2>&1 &
	echo $! >"$d/pid"
}
q() { # q NAME SQL: run SQL on a member's local socket
	local n=$1
	shift
	runuser -u postgres -- psql -X -h "$work/$n/sock" -p 5499 -d appdb -Atc "$*" 2>/dev/null
}
wait_for() { # wait_for DESCRIPTION CMD...
	local what=$1 i
	shift
	for i in $(seq 1 90); do
		if "$@" >/dev/null 2>&1; then return 0; fi
		sleep 1
	done
	fail "timed out waiting for $what"
}
ready() { [ "$(q "$1" 'select 1')" = 1 ]; }
is_primary() { [ "$(q "$1" 'select pg_is_in_recovery()')" = f ]; }
is_replica() { [ "$(q "$1" 'select pg_is_in_recovery()')" = t ]; }
streaming() { [ "$(q "$1" "select status from pg_stat_wal_receiver")" = streaming ]; }
has_row() { [ "$(q "$1" "select count(*) from t where v = '$2'")" = 1 ]; }
stop_clean() { runuser -u postgres -- pg_ctl stop -m fast -D "$work/$1/data/pgdata" -w >/dev/null; wait "$(cat "$work/$1/pid")" 2>/dev/null || true; }

# 1. a new primary: initdb, accounts, database
member m1
role m1 primary
set_rw $ip1
start m1 $ip1 primary
wait_for "m1 to accept connections" ready m1
wait_for "m1 to create the application database" test "$(q m1 "select count(*) from pg_roles where rolname in ('app','replicator')")" = 2
is_primary m1 || fail "m1 is not a primary"
[ "$(q m1 'show data_checksums')" = on ] || fail "data checksums are off"
q m1 "create table t (v text); insert into t values ('one')" >/dev/null
ok "a new primary initialises its database, accounts and checksums"

# 2. a replica takes a base backup and streams
member m2
role m2 replica
start m2 $ip2 replica
wait_for "m2 to accept connections" ready m2
wait_for "m2 to stream" streaming m2
is_replica m2 || fail "m2 is not in recovery"
wait_for "m2 to have the row" has_row m2 one
[ "$(q m1 "select count(*) from pg_replication_slots where slot_name = 'ziro_m2'")" = 1 ] || fail "m2 has no slot on the primary"
[ "$(q m1 "select application_name from pg_stat_replication")" = m2 ] || fail "m2 does not report its member name"
q m1 "insert into t values ('two')" >/dev/null
wait_for "m2 to replay a later write" has_row m2 two
ok "a replica is copied from a running primary, streams through its slot and keeps up"

# 3. promote m2; the old primary crashes; it comes back as a replica of the new primary
runuser -u postgres -- pg_ctl promote -D "$work/m2/data/pgdata" -w >/dev/null
role m2 primary 1
role m1 replica 1
set_rw $ip2
wait_for "m2 to be a primary" is_primary m2
q m2 "insert into t values ('three')" >/dev/null
# The controller creates the replicas' slots on the new primary (order "slots") right after a promotion.
q m2 "select pg_create_physical_replication_slot('ziro_m1')" >/dev/null
kill -9 "$(cat "$work/m1/pid")" 2>/dev/null || true
pkill -9 -u postgres -f "$work/m1/data" 2>/dev/null || true
sleep 1
rm -f "$work/m1/data/pgdata/postmaster.pid"
start m1 $ip1 primary
wait_for "m1 to rejoin" ready m1
wait_for "m1 to stream from m2" streaming m1
is_replica m1 || fail "m1 should be a replica"
wait_for "m1 to have the row written on m2" has_row m1 three
grep -q "pg_rewind failed; copying the primary\|rewound to the primary" "$work/m1/log" || fail "m1 did not rejoin through rewind or a new base backup"
ok "a crashed old primary rejoins the new primary (rewind, or a new base backup when it was not shut down cleanly)"

# 4. a stale role file: m1 is told it is the primary, but the read-write name is served by m2
stop_clean m1
rm -f "$work/m1/data/pgdata/standby.signal"
role m1 primary 1
start m1 $ip1 primary
wait_for "m1 to be ready" ready m1
wait_for "m1 to follow m2" streaming m1
is_replica m1 || fail "m1 started as a primary while m2 was serving"
grep -q "not starting as primary" "$work/m1/log" || fail "the refusal was not logged"
ok "a former primary refuses to serve while the read-write name has another primary"

# 5. a rebuild was requested (ziroctl pg reinit): the replica discards its data and copies the primary
stop_clean m1
echo local-only >"$work/m1/data/pgdata/SENTINEL"
touch "$work/m1/data/pgdata/ziro-reinit"
role m1 replica 1
start m1 $ip1 replica
wait_for "m1 to be rebuilt and accept connections" ready m1
wait_for "m1 to stream again" streaming m1
is_replica m1 || fail "m1 should be a replica"
[ ! -e "$work/m1/data/pgdata/SENTINEL" ] || fail "the old data directory was kept"
[ ! -e "$work/m1/data/pgdata/ziro-reinit" ] || fail "the marker was left behind"
grep -q "rebuild requested: discarding this data directory" "$work/m1/log" || fail "the rebuild was not logged"
grep -q "taking a base backup" "$work/m1/log" || fail "no new base backup was taken"
wait_for "m1 to have the data again" has_row m1 three
ok "a replica with the rebuild marker discards its data and takes a new base backup"

# 6. the same marker on the primary is ignored: nothing is wiped
stop_clean m2
echo keep-me >"$work/m2/data/pgdata/SENTINEL"
touch "$work/m2/data/pgdata/ziro-reinit"
role m2 primary 1
start m2 $ip2 replica
wait_for "m2 to accept connections" ready m2
is_primary m2 || fail "m2 should still be the primary"
[ -e "$work/m2/data/pgdata/SENTINEL" ] || fail "the primary's data directory was wiped"
[ ! -e "$work/m2/data/pgdata/ziro-reinit" ] || fail "the marker was left behind on the primary"
grep -q "this member is the primary: ignored" "$work/m2/log" || fail "the refusal was not logged"
has_row m2 three || fail "the primary lost its data"
ok "the rebuild marker on a primary is ignored and its data stays"

echo "pass: $pass checks against PostgreSQL $major"
