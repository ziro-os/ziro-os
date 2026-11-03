#!/bin/bash
# Runs the Postgres member entry script (tools/ziroctl/cmd/pg_entry.sh) against real PostgreSQL
# binaries, outside a container: a primary, a replica taken with pg_basebackup, a promotion, and the
# old primary rejoining by pg_rewind (clean stop) or a new base backup (crash), including the refusal
# to start as primary when another primary is serving; members talk TLS (verify-ca) to each other, the
# superuser cannot log in over the network, and the lease watchdog fences a primary whose lease ended.
# Backups: WAL archiving and a point-in-time restore into a new primary run through the entry script
# with a stand-in for pgbackrest (tests/pg/pgbackrest-standin.sh: a directory for the repository, the
# same command line and the same recovery settings). It needs root (it plays the container), the
# PostgreSQL server binaries and util-linux's runuser and setpriv, and it edits /etc/hosts for the test names
# (removed on exit). Usage: tests/pg/entry-test.sh   (exit 0 = pass, 77 = skipped).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
entry="$here/../../tools/ziroctl/cmd/pg_entry.sh"

[ "$(id -u)" = 0 ] || { echo "skip: needs root"; exit 77; }
bindir=$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1 || true)
[ -n "$bindir" ] && [ -x "$bindir/initdb" ] || { echo "skip: no PostgreSQL server binaries"; exit 77; }
command -v runuser >/dev/null || { echo "skip: no runuser"; exit 77; }
command -v setpriv >/dev/null || { echo "skip: no setpriv"; exit 77; }
command -v openssl >/dev/null || { echo "skip: no openssl"; exit 77; }
id postgres >/dev/null 2>&1 || { echo "skip: no postgres user"; exit 77; }
major=$(basename "$(dirname "$bindir")")

work=$(mktemp -d /tmp/ziro-pg-test.XXXXXX)
chmod 755 "$work"
mkdir "$work/bin"
# The Ziro Postgres image's gosu (images/postgres/gosu.sh), as the entry script runs it there.
install -m 755 "$here/../../images/postgres/gosu.sh" "$work/bin/gosu"
export PATH="$work/bin:$bindir:$PATH"

# A cluster CA and a server certificate, as pg_tls.go makes them.
(
	cd "$work"
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.crt -days 2 -subj "/CN=test CA" 2>/dev/null
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout server.key -out server.csr -subj "/CN=rw.pgtest" 2>/dev/null
	openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 2 2>/dev/null
)
b64() { base64 -w0 <"$work/$1"; }
TLS_CA=$(b64 ca.crt) TLS_CERT=$(b64 server.crt) TLS_KEY=$(b64 server.key)

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
		PG_TLS_CA="$TLS_CA" PG_TLS_CERT="$TLS_CERT" PG_TLS_KEY="$TLS_KEY" \
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

# 7. a member that already served a database comes back with an empty data directory: it must not
# create a new empty database (that would silently replace the lost one); it stays down so the
# controller fails over to a replica
member m3
printf 'role=primary\nepoch=2\ninitialised=1\n' >"$work/m3/cfg/role"
start m3 $ip2 primary
rc=0
wait "$(cat "$work/m3/pid")" || rc=$?
[ "$rc" -ne 0 ] || fail "a member that had served a database initialised a new one"
[ ! -e "$work/m3/data/pgdata/PG_VERSION" ] || fail "an empty database was created"
grep -q "refusing to create a new one" "$work/m3/log" || fail "the refusal was not logged"
ok "an empty data directory on a member that served before is refused, not re-initialised"

# 8. a base backup that died half way left a PG_VERSION behind: without the marker the next start would
# run Postgres on it for ever. The marker makes the entry script copy the primary again
stop_clean m1
echo half-copied >"$work/m1/data/pgdata/M1-ONLY"
touch "$work/m1/data/ziro-building" "$work/m1/data/ziro-busy"
start m1 $ip1 replica
wait_for "m1 to be copied again" ready m1
wait_for "m1 to stream again" streaming m1
[ ! -e "$work/m1/data/pgdata/M1-ONLY" ] || fail "the unfinished copy was kept"
[ ! -e "$work/m1/data/ziro-building" ] || fail "the building marker was left behind"
[ ! -e "$work/m1/data/ziro-busy" ] || fail "the busy file was left behind"
grep -q "did not finish: discarding" "$work/m1/log" || fail "the discard was not logged"
ok "an unfinished base backup is discarded and taken again"

# 9. starts that never ran healthy, but no primary answers: the data stays (it may be the only copy)
stop_clean m1
echo keep-me >"$work/m1/data/pgdata/M1-ONLY"
echo 9 >"$work/m1/data/ziro-starts"
set_rw 127.0.0.99
start m1 $ip1 replica
wait_for "m1 to accept connections" ready m1
[ -e "$work/m1/data/pgdata/M1-ONLY" ] || fail "a replica was rebuilt although no primary answered"
grep -q "no primary answers: keeping the data directory" "$work/m1/log" || fail "the decision was not logged"
ok "a crash-looping replica is not rebuilt while no primary answers"

# 10. the same, with a primary: the replica takes a new base backup instead of looping
stop_clean m1
set_rw $ip2
echo 9 >"$work/m1/data/ziro-starts"
start m1 $ip1 replica
wait_for "m1 to be rebuilt" ready m1
wait_for "m1 to stream again" streaming m1
[ ! -e "$work/m1/data/pgdata/M1-ONLY" ] || fail "the data directory was kept"
grep -q "starts in a row did not run healthy: taking a new base backup" "$work/m1/log" || fail "the rebuild was not logged"
ok "a replica that never runs healthy is rebuilt from the primary"

# 11. a start that cannot proceed says why where the agent can read it
member m4
printf 'role=replica\nepoch=2\n' >"$work/m4/cfg/role"
set_rw 127.0.0.99
ZIRO_PG_MAX_STARTS=4 start m4 $ip2 replica
rc=0
wait "$(cat "$work/m4/pid")" || rc=$?
[ "$rc" -ne 0 ] || fail "a replica with no primary to copy started"
grep -q "^no primary at rw.pgtest" "$work/m4/data/ziro-last-error" || fail "the reason was not written for the agent"
ok "a start that fails records its reason"

# 12. TLS between members, and who may log in over the network
set_rw $ip2
wait_for "m1 to stream from m2" streaming m1
[ "$(q m2 'show ssl')" = on ] || fail "the primary does not serve TLS"
[ "$(q m2 "select s.ssl from pg_stat_replication r join pg_stat_ssl s using (pid)")" = t ] || fail "replication is not encrypted"
tcp() { PGCONNECT_TIMEOUT=3 PGPASSWORD=$3 runuser -u postgres -- psql -X -h "$ip2" -p 5499 -U "$2" -d appdb "sslmode=$1" -Atc 'select 1' 2>&1; }
[ "$(PGCONNECT_TIMEOUT=3 PGPASSWORD=apppass runuser -u postgres -- psql -X "host=$ip2 port=5499 user=app dbname=appdb sslmode=verify-ca sslrootcert=$work/ca.crt" -Atc 'select ssl from pg_stat_ssl where pid = pg_backend_pid()')" = t ] ||
	fail "the application user cannot connect with TLS checked against the cluster CA"
PGCONNECT_TIMEOUT=3 PGPASSWORD=superpass runuser -u postgres -- psql -X "host=$ip2 port=5499 user=postgres dbname=appdb" -Atc 'select 1' >/dev/null 2>&1 &&
	fail "the superuser logged in over the network"
ok "members replicate over TLS checked against the cluster CA; the superuser is local only"

# 13. the lease watchdog: a primary whose lease ended stops acknowledging commits, and starts again when renewed
printf 'grant=1\nttl=22\nepoch=1\nfence=1\n' >"$work/m2/cfg/lease"
echo "$(($(date +%s) + 60)) 1" >"$work/m2/cfg/lease-until"
sleep 3
[ "$(q m2 'show synchronous_standby_names')" = "" ] || fail "a primary with a valid lease was fenced"
q m2 "alter system set synchronous_standby_names = 'ANY 1 (m1)'" >/dev/null
q m2 "select pg_reload_conf()" >/dev/null
echo "$(($(date +%s) - 1)) 1" >"$work/m2/cfg/lease-until"
fenced() { [ "$(q m2 'show synchronous_standby_names')" = ziro_fenced ]; }
wait_for "m2 to fence itself" fenced
grep -q "lease from the master ended" "$work/m2/log" || fail "the fence was not logged"
# A commit waits for the fence standby, which never comes: no acknowledgement within 10 s (statement_timeout
# does not apply to the wait for a synchronous standby, so the client is stopped from outside).
rc=0
out=$(timeout 10 runuser -u postgres -- psql -X -h "$work/m2/sock" -p 5499 -d appdb -c "insert into t values ('fenced')" 2>&1) || rc=$?
[ "$rc" = 124 ] && ! printf '%s' "$out" | grep -q 'INSERT 0 1' || fail "a commit was acknowledged while fenced (rc $rc): $out"
echo "$(($(date +%s) + 60)) 1" >"$work/m2/cfg/lease-until"
unfenced() { [ "$(q m2 'show synchronous_standby_names')" = "ANY 1 (m1)" ]; }
wait_for "m2 to lift the fence" unfenced
q m2 "insert into t values ('after-fence')" >/dev/null || fail "no commit after the lease came back"
ok "a primary fences itself when its lease ends and restores its standby list when it is renewed"

# 14. a primary that restarts without a lease starts fenced
echo "$(($(date +%s) - 1)) 1" >"$work/m2/cfg/lease-until"
wait_for "m2 to fence itself" fenced
stop_clean m2
start m2 $ip2 primary
wait_for "m2 to accept connections" ready m2
fenced || fail "a primary without a lease started unfenced"
grep -q "no lease from the master: starting fenced" "$work/m2/log" || fail "the fenced start was not logged"
echo "$(($(date +%s) + 60)) 1" >"$work/m2/cfg/lease-until"
wait_for "m2 to lift the fence" unfenced
ok "a primary that restarts without a lease starts fenced and is released when the lease comes"

# 15. a group without replicas (fence=0) is never fenced
printf 'grant=0\nttl=22\nepoch=1\nfence=0\n' >"$work/m2/cfg/lease"
echo "$(($(date +%s) - 1)) 1" >"$work/m2/cfg/lease-until"
sleep 3
fenced && fail "a primary with nothing to fail over to was fenced"
ok "a primary with no replica to fail over to is not fenced"

# 16. backups: WAL goes to the repository, and a restore to a point in time makes a new primary
stop_clean m1 2>/dev/null || true
stop_clean m2 2>/dev/null || true
ip3=127.0.0.13 ip4=127.0.0.14
{
	echo "$ip3 m3.pgtest $hosts_mark"
	echo "$ip4 m4.pgtest $hosts_mark"
} >>/etc/hosts
install -m 755 "$here/pgbackrest-standin.sh" "$work/bin/pgbackrest"
mkdir -p "$work/repo"
chown postgres "$work/repo"
export STANDIN_REPO="$work/repo" ZIRO_PG_STANZA=main STANDIN_REPO_PATH=/ziro/db
member m3
role m3 primary
set_rw $ip3
start m3 $ip3 primary
wait_for "m3 to accept connections" ready m3
wait_for "m3 to create the application database" test "$(q m3 "select count(*) from pg_roles where rolname in ('app','replicator')")" = 2
[ "$(q m3 'show archive_mode')" = on ] || fail "archiving is off with a stanza"
[ "$(q m3 'show archive_command')" = 'pgbackrest --stanza=main archive-push %p' ] || fail "archive_command: $(q m3 'show archive_command')"
q m3 "create table t (v text); insert into t values ('before')" >/dev/null
runuser -u postgres -- env PGPASSWORD=replpass PGSSLMODE=require pg_basebackup -h $ip3 -p 5499 -U replicator \
	-D "$work/repo/ziro/db/main/base" -X none --checkpoint=fast --no-password 2>>"$work/m3/log" || fail "the base backup failed"
q m3 "insert into t values ('mid')" >/dev/null
sleep 1
target=$(q m3 "select now()")
sleep 1
q m3 "insert into t values ('after')" >/dev/null
seg=$(q m3 "select pg_walfile_name(pg_current_wal_lsn())")
q m3 "select pg_switch_wal()" >/dev/null
archived() { [ "$(q m3 "select last_archived_wal from pg_stat_archiver")" = "$seg" ]; }
wait_for "m3 to archive $seg" archived
[ "$(q m3 "select failed_count from pg_stat_archiver")" = 0 ] || fail "archiving failed"
[ -f "$work/repo/ziro/db/main/archive/$seg" ] || fail "the segment is not in the repository"
ok "a member with backups archives its WAL into the repository"

stop_clean m3
export STANDIN_REPO_PATH=/ziro/db2 ZIRO_PG_RESTORE_PATH=/ziro/db ZIRO_PG_RESTORE_STANZA=main ZIRO_PG_RESTORE_TARGET="$target"
member m4
role m4 primary
set_rw $ip4
start m4 $ip4 restore
restored() { is_primary m4 && [ "$(q m4 "select count(*) from pg_roles where rolname = 'app'")" = 1 ]; }
wait_for "m4 to restore and promote" restored
grep -q "restoring from the backup repository (/ziro/db, stanza main, $target)" "$work/m4/log" || fail "the restore was not logged"
has_row m4 before && has_row m4 mid || fail "rows before the target are missing"
has_row m4 after && fail "a row written after the target was restored"
[ "$(q m4 "select timeline_id from pg_control_checkpoint()")" -ge 2 ] || fail "the restored primary is on the old timeline"
q m4 "insert into t values ('restored')" >/dev/null || fail "the restored primary does not take writes"
q m4 "select pg_switch_wal()" >/dev/null
wait_for "m4 to archive into its own repository" test -n "$(ls "$work/repo/ziro/db2/main/archive" 2>/dev/null)"
ok "a restore to a point in time keeps what was committed before it, drops what came after, and archives to its own repository"

stop_clean m4
start m4 $ip4 restore
wait_for "m4 to accept connections" ready m4
is_primary m4 || fail "the restored primary came back in recovery"
grep -Eq '^(restore_command|recovery_target)' "$work/m4/data/pgdata/postgresql.auto.conf" && fail "the restore's recovery settings are left in place"
has_row m4 restored || fail "a row is missing after the restart"
[ "$(grep -c 'restoring from the backup repository' "$work/m4/log")" = 1 ] || fail "a restart restored again"
ok "a restored primary restarts on its own data, without the restore's recovery settings"
unset STANDIN_REPO STANDIN_REPO_PATH ZIRO_PG_STANZA ZIRO_PG_RESTORE_PATH ZIRO_PG_RESTORE_STANZA ZIRO_PG_RESTORE_TARGET

echo "pass: $pass checks against PostgreSQL $major"
