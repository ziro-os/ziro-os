# Postgres clusters

`ziroctl pg` runs PostgreSQL on a Ziro cluster as a primary with streaming replicas on different nodes. It fails
over by itself, adds and removes replicas without interrupting the primary, and with Citus spreads tables over
several primaries so that writes scale out. The design is in
[RFC 0005](design/rfcs/0005-postgres-clusters.md).

Use `ziroctl pg` for anything that must survive a node. The catalog `postgres` app is a single instance: it cannot be
scaled, because a second replica would be an independent, empty database (see [Apps](apps.md#scaling)).

## Quick start

On the cluster master:

```sh
ziroctl pg create shop --replicas 2 --memory 4Gi --cpus 2
ziroctl pg status shop
ziroctl pg credentials shop
```

This creates a primary and two replicas on three different nodes. The cluster needs at least that many Ready nodes
(`--colocate` lets members share a node, for development only). Apps and containers on the cluster connect with:

| Name | Points at |
| --- | --- |
| `shop-rw.cluster.ziro` | the primary (reads and writes) |
| `shop-ro.cluster.ziro` | replicas that are caught up (the primary when there are none) |

The names follow the roles. After a failover they point at the new primary within seconds, and clients only need to
reconnect; no app is restarted or reconfigured. Use a driver that retries on connection errors, and for read
traffic use the `-ro` name.

Applications with many connections (or many replicas each holding a pool) should go through the
[pooler](#connection-pooling) at `shop-pool.cluster.ziro` instead: database `app` for writes, `app_ro` for reads.

To reach the database from outside the cluster, publish it through the [gateway](gateway.md):

```sh
ziroctl pg expose shop --port 5432 --allow 203.0.113.0/24
ziroctl pg expose shop --port 5433 --ro --allow 10.0.0.0/8
```

`--allow` is required (`--allow 0.0.0.0/0` publishes to anyone), so a database is never open to the internet by
accident.

Passwords are cluster secrets; they are shown only by `ziroctl pg credentials` on the master and are never served
over the API. See [Security](#security) for TLS and password rotation.

## Replication and durability

| Setting | Behavior |
| --- | --- |
| `--sync quorum` (default) | With two replicas a commit waits for one of them, with three or more for two (`ANY k (m2, m3, ...)`). A failover loses no acknowledged write, and an isolated old primary cannot commit. With one replica replication is asynchronous, because waiting for the only replica would stop writes when it is down. |
| `--sync off` | Always asynchronous: the fastest commits; a failover can lose the writes the replica had not received. |

`ziroctl pg create` makes two replicas unless told otherwise. With `--replicas 1` (or `--sync off`) it says that
replication is asynchronous.

Every replica has a physical replication slot on the primary, and `max_slot_wal_keep_size` keeps a replica that is
gone for good from filling the primary's disk. A replica that falls too far behind is rebuilt from a new base
backup.

Data checksums and `scram-sha-256` are on.

## Performance

Memory and CPU limits tune the members: `shared_buffers` (a quarter of memory), `effective_cache_size`, `work_mem`,
`maintenance_work_mem`, parallel and autovacuum workers. Every cluster also gets:

- `pg_stat_statements` and `auto_explain` (statements slower than 5 s are logged with their plan);
  `create extension pg_stat_statements` in a database to query it;
- `jit` off, WAL compressed with lz4, checkpoints every 15 minutes, autovacuum triggered earlier (5 % of a table)
  and allowed more I/O, `idle_in_transaction_session_timeout` of 30 minutes (a forgotten open transaction stops
  vacuum for every table);
- on PostgreSQL 18, asynchronous I/O with a worker per CPU (`io_method = worker`).

Settings a hot standby must have at least as high as its primary (`max_connections`, `max_worker_processes`) do not
follow the limits, so resizing down never stops a replica.

### Change parameters

```sh
ziroctl pg set shop work_mem=64MB statement_timeout=30s
ziroctl pg set shop max_connections=400
ziroctl pg set shop statement_timeout=
```

`pg set` takes a closed list of parameters, each checked by type and range (`ziroctl pg set --help` lists them).
Parameters Postgres reloads take effect within a heartbeat on every member, without a restart. The others
(`shared_buffers`, `max_connections`, ...) restart the members one at a time with the primary last after a
switchover. `param=` puts a parameter back to its default. `max_connections`, `max_worker_processes` and
`max_locks_per_transaction` can only grow. Replication, TLS and the standby list are not settable: the controller
owns them.

### Resize, upgrade, restart

```sh
ziroctl pg resize shop --memory 8Gi --cpus 4
ziroctl pg upgrade shop --image docker.io/library/postgres:17.7@sha256:<digest>
ziroctl pg restart shop
```

Each restarts the members one at a time, every member back and caught up before the next, with the primary last
after a switchover: writes pause only for the switchover. `pg upgrade` takes an image of the same major version
pinned by digest (minor versions, security rebuilds).

## Connection pooling

New clusters have PgBouncer in front of them, as two stateless replicas at `<name>-pool.cluster.ziro`:

| Database | Goes to |
| --- | --- |
| `app` | the primary (`-rw`) |
| `app_ro` | the replicas (`-ro`) |

Transaction pooling lets thousands of client connections share a few dozen server connections, which keeps
`max_connections` (and the memory each costs) small. The pooler follows failovers: it resolves the role-following
names with a 5 s cache. It talks TLS to the members (`verify-ca`) and offers TLS to its clients, and it holds only
the application user's password.

```sh
ziroctl pg pool shop --size 40            # server connections per database
ziroctl pg pool shop --mode session       # for clients that rely on session state
ziroctl pg pool shop --disable
ziroctl pg create events --no-pooler
```

Transaction mode does not keep session state between transactions: session-level `SET`, advisory locks held across
transactions and `LISTEN` need `--mode session` or a direct connection to `-rw`. `ziroctl pg credentials` prints
the pooled connection strings.

## Failover

The agent on each node checks every member every 5 seconds. The controller on the cluster leader declares the
primary failed when its node is down or it has not answered for 36 seconds, and then:

1. picks the replica that holds the most WAL (received, not only replayed: a replica holding an acknowledged
   commit wins). With asynchronous replication it must be within 16 MiB of the
   failed primary's last known position: a further-behind replica is promoted only by an operator with
   `ziroctl pg failover --force`, since that loses writes;
2. refuses to promote unless the replicas it can reach could have received every synchronous commit, so a minority
   cannot promote itself next to a live primary (with `--sync quorum`);
3. raises the cluster epoch, orders the promotion, and moves `-rw` to the new primary when it confirms;
4. points every replica at the new primary by name (a replica still streaming from the old primary would not move
   by itself), and keeps a replica that is on an older timeline out of `-ro`;
5. fences the old primary: when it returns, its entry script finds another primary behind `-rw`, refuses to serve,
   and rejoins as a replica with `pg_rewind`, or from a new base backup when the rewind is not possible.

The primary also fences itself. Every heartbeat the master grants each member a lease, as long as its probe is
fresh. A watchdog in the primary's container checks the lease every second. When the lease has ended, it sets
`synchronous_standby_names` to a standby that does not exist and ends client sessions, so no further commit is
acknowledged. It gives the standby list back when the lease returns. A primary that restarts without a lease starts
fenced.

The lease lasts 22 seconds from the heartbeat that carried a fresh probe, and the master waits 36 seconds before it
fails the primary over. So the old primary has stopped acknowledging writes before a replica takes over, whatever
silenced it: its node failing, a network cut, or a hung container runtime. A group with no replica has nothing to
fail over to and is never fenced. With a single master, the primaries of clusters with replicas stop acknowledging
writes while that master is down. Run three masters for production
([Clustering](clustering.md#high-availability-control-plane)).

The controller does nothing while the cluster is partitioned or when probe data is stale. `ziroctl pg pause shop`
stops it from changing roles at all (for maintenance) and `ziroctl pg resume shop` brings it back. Every promotion
is an alert in the category `database` and is listed in `ziroctl pg status`.

### What the controller repairs by itself

- **A replica that cannot follow.** A replica that answers but has not made progress for 10 minutes (it is not
  streaming, or its WAL position does not move) is rebuilt from the primary, as `ziroctl pg reinit` does. A long
  catch-up that is still gaining is progress and is left alone.
- **A replica whose container does not come up** (it crash-loops, its data directory is unusable, it never
  started) is rebuilt the same way after 10 minutes, 20 for one that has never reported (its first image pull and
  base backup take time), as long as its node is up and the primary answers. A member that is copying the primary's
  data is not stuck and is never interrupted, however long the copy takes. A member still broken between one and
  six hours after its rebuild is replaced by a new member (at most one replacement per group every six hours).
  One on a node that has been gone for 10 minutes is replaced on another node.
- **A replica that is stuck again** within an hour of its rebuild is left alone, with an alert: the cause is then
  not its data.
- **A primary left read-only** by an aborted switchover is made writable again.
- **The synchronous standby list** is sent to every new primary after a promotion, even when it is empty, so commits
  never wait for replicas that are not there.
- **A replica on an older timeline** than the primary it would replace is not a promotion candidate.
- **A member that served a database and comes back with an empty data directory** (a replaced disk) is not
  initialised again as a new empty database: it stays down, and the controller fails over to a replica.
- **A new cluster leader** waits 60 seconds for the members to report before it fails anything over, so a primary
  that is only slow to report after a reboot does not lose its place.
- **A replica being removed** leaves after 10 minutes even if the synchronous list could not be updated.

Repeated failures of the same command raise one alert per quarter hour, not one per attempt, and `ziroctl pg status`
shows what each group is waiting for.

### When the controller does not fail over

`ziroctl pg status shop` ends each group with lines starting `!` that say why it is not healthy: a paused
controller, a primary that stopped answering, no replica that can be promoted, too few replicas reachable for a safe
promotion, a replica far behind, a partition, a command that failed or has not completed, a replica that is not
streaming. When the reason is one of the safety refusals, an operator can decide:

```sh
ziroctl pg failover shop                # now, with the automatic safety checks (skips the 36 s wait and the partition brake)
ziroctl pg failover shop --to m3 --force  # promote m3 even if acknowledged writes may be lost
```

`failover` is for a primary that is down and is refused while it answers (use a switchover). Without `--force` it
keeps the checks of an automatic failover; with `--force` it promotes any replica that answers and the alert says
that writes may be lost. A request that finds no replica to promote expires after two minutes.

### Rebuild a replica

```sh
ziroctl pg reinit shop m3
```

Discards the replica's data directory and takes a new base backup from the primary, for a replica that cannot catch
up (a replication slot lost to WAL growth, a diverged timeline). The primary is never touched: the command is
refused for any member that is not a replica, and the agent checks that the member is in recovery before it changes
anything.

It also works on a replica that shows `down` or `starting` in `pg status`. Its container cannot be asked, so the node
leaves a marker on the data directory and restarts the container; the entry script then copies the primary. The
`!` line for such a member says what the node sees (the container's state, and the last error its start script
recorded, for example `no primary at shop-main-rw.cluster.ziro yet`).

A start that is cut short never leaves a half-copied data directory in use: a marker next to the data directory is
set before a base backup or rewind and removed when it finishes, and a replica that has started four times without
once running healthy for a minute takes a new base backup, but only while a primary answers.

### Planned switchover

```sh
ziroctl pg switchover shop              # to the replica furthest ahead
ziroctl pg switchover shop --to m3
```

The primary is made read-only and fenced: commits under way wait instead of being acknowledged, so none can be lost,
even from a session that turned read-only off for itself. The target catches up and is promoted, `-rw` moves, and
the old primary becomes a replica. Writes pause for a few seconds. Use it before maintenance on the primary's node.
An aborted switchover gives the primary its standby list back.

### Upgrades and configuration changes

A change to a member's container is rolled out one member at a time. This covers a ziroctl upgrade that changes
the entry script, new memory or CPU limits, a new image, and a password change. Each replica restarts in turn, and
the next waits until it is back, streaming and caught up. The primary goes last, after a switchover to a replica
that already runs the new configuration, so writes pause only for the switchover. A member that is down anyway is
not waited for, and a group with no replica restarts its primary in place.

### Maintenance windows

By default those changes roll out at once. A maintenance window holds them until a time you choose:

```sh
ziroctl pg maintenance shop --window '0 2 * * 0' --duration 2h   # Sundays 02:00-04:00 UTC
ziroctl pg maintenance shop --open 1h                            # open it now, for an hour
ziroctl pg maintenance shop --clear                              # no window: changes roll out at once
```

The window is a five-field cron expression in UTC for when it opens, and a duration (30 minutes to 24 hours) for
how long it stays open.

- **What waits:** a new image, restart-only parameters, a resize, `pg restart`, and a ziroctl upgrade that changes
  the members. Until the window opens, the members keep running and `pg status` lists the ones waiting, with the
  next opening time.
- **What never waits:** failover, a switchover you ask for, repairs (rebuilding a replica, replacing a member on a
  gone node), members that are not serving anyway, and the restarts that follow a password change.

## Roles and databases

Each app can have its own login instead of sharing the application user's:

```sh
ziroctl pg role shop web                              # reads and writes every table
ziroctl pg role shop reports --access readonly        # reads only
ziroctl pg db shop analytics --owner web --extension pg_trgm
ziroctl pg db shop app --extension pgcrypto           # extensions in the cluster's own database
ziroctl pg roles shop                                 # what exists, and whether it is applied yet
ziroctl pg credentials shop --role reports
```

### Roles

- **Access.** `readwrite` grants PostgreSQL's `pg_read_all_data` and `pg_write_all_data`; `readonly` grants only
  the first.
- **Passwords.** Each role gets a generated password, kept in its own cluster secret `pg-shop-role-<role>` with
  `PGPASSWORD`, `DATABASE_URL` and `DATABASE_URL_RO`. The primary receives only the password's SCRAM verifier, never
  the password.
- **Removing.** `pg role shop reports --rm` stops the role from logging in (`NOLOGIN`) and deletes its credentials.
  Its objects and grants stay.

### Databases

- **Owner and extensions.** A database has an owner (the application user, or a role, which can then create tables
  in it) and extensions from the image that need no preloading: `amcheck`, `bloom`, `btree_gin`, `btree_gist`,
  `citext`, `cube`, `dict_int`, `earthdistance`, `fuzzystrmatch`, `hstore`, `intarray`, `isn`, `lo`, `ltree`,
  `pg_buffercache`, `pg_prewarm`, `pg_stat_statements`, `pg_trgm`, `pgcrypto`, `pgstattuple`, `postgres_fdw`, `seg`,
  `tablefunc`, `tcn`, `unaccent` and `uuid-ossp`.
- **Removing.** `pg db shop analytics --rm` stops managing a database. It is never dropped.

### How changes are applied

The controller applies one change at a time on the primary. A database waits for its
owner role. A failed change is retried after a minute, and its alert repeats at most every 15 minutes.

### Connecting an app

`--pg` gives an app its credentials and lets it connect:

```sh
ziroctl apps deploy myapp --pg shop          # the application user: DATABASE_URL, DATABASE_URL_RO, DATABASE_POOL_URL
ziroctl apps deploy myapp --pg shop:web      # the role web: DATABASE_URL, DATABASE_URL_RO, PGPASSWORD
```

Each component of the app loads the secret as environment variables and is added to the cluster's `allow_from`.
The secrets follow password changes, so restart the app after `pg rotate-password` to pick up the new password.

## Declarative clusters

A cluster can be described in a file and applied, like a [host config](provisioning.md):

```yaml
postgres:
  version: 1
  name: shop
  postgres: "17"
  replicas: 2
  resources: {memory: 4Gi, cpus: 2}
  allow_from: [web, worker]
  params:
    work_mem: 64MB
    statement_timeout: 30s
  pooler: {enabled: true, mode: transaction, size: 40}
  backup:
    endpoint: s3.eu-west-1.amazonaws.com
    bucket: acme-db
    region: eu-west-1
    retention: 8
    schedule: {full: "0 1 * * 0", incr: "30 * * * *"}
  maintenance: {window: "0 2 * * 0", duration: 2h}
  roles:
    - {name: web}
    - {name: reports, access: readonly, database: analytics}
  databases:
    - {name: analytics, owner: web, extensions: [pg_trgm]}
```

```sh
ziroctl pg apply -f shop.yaml --dry-run    # the plan only
ziroctl pg apply -f shop.yaml
ziroctl pg get shop > shop.yaml            # the cluster as it is, as a file
ziroctl pg diff -f shop.yaml               # what applying it would change
```

How a file is applied:

- **The plan comes first.** Each line is marked `+` create, `~` update, `=` unchanged, `-` remove or `!` refused,
  with what restarts members.
- **The plan is exact.** It runs the same operations as the `pg` commands, on a copy of the cluster state, so a dry
  run reports what an apply would refuse.
- **All or nothing.** If any part is refused, nothing changes. Refused changes are a different major version, sync
  mode, database or user, fewer shards, a plain cluster becoming sharded, and a parameter that can only grow going
  back down.
- **A field left out keeps its current value**, or takes its default when the cluster is created. A short file
  never scales a cluster down or resumes a paused one by accident.
- **`params`, `allow_from`, `roles` and `databases` are whole lists** when given. A parameter left out goes back to
  its default, a role left out can no longer log in, and a database left out is no longer managed (never
  dropped). A role may connect to a database the same file adds, and a database may be owned by a role it adds.
- **Turning things off is explicit:** `pooler: {enabled: false}`, `backup: {enabled: false}` (the backups stay in
  the bucket), `maintenance: {}`, `paused: false`.
- **No secret goes in the file.** Passwords are generated. When the file turns backups on, the repository's keys
  come from `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.
- **Applying the same file twice changes nothing**, and neither does applying what `pg get` printed.

Over the API: `GET /api/v1/pg/{name}/spec` returns the file, `POST /api/v1/pg-plan` (operator) plans one and
`POST /api/v1/pg-apply` (admin) applies it. The schema is `PostgresConfig` in
[`sdk/schema`](../sdk/schema/postgres.go).

## Add and remove replicas

```sh
ziroctl pg add-replica shop                  # on the least loaded node without a member
ziroctl pg add-replica shop --node node-4
ziroctl pg add-replica shop --from m2        # copy from a replica to spare the primary
ziroctl pg scale shop --replicas 4
ziroctl pg rm-replica shop m4
```

A new replica copies the primary with `pg_basebackup` through its own slot, so the primary keeps serving; nothing is
changed or reloaded on it (the synchronous setting names every standby). The replica joins `-ro` only when it has
caught up. Removing one takes it out of `-ro`, drops its slot and deletes its data. Adding or removing a replica
never changes the primary.

## Sharding with Citus

One primary takes all writes. For more write throughput, create the cluster with worker groups:

```sh
ziroctl pg create events --replicas 1 --shards 3 --citus-image docker.io/citusdata/citus:13.2.0@sha256:<digest>
ziroctl pg add-shard events
```

`--shards 3` creates a coordinator group and three worker groups. Each group has its own primary and replicas, so a
worker failure is an ordinary failover. The controller registers the workers by their `-rw` names, so a failover
needs no change in Citus, and enables metadata sync, so any node can run distributed queries. Connect to
`events-rw.cluster.ziro` (the coordinator) and distribute your tables by the key your queries filter on:

```sql
CREATE TABLE orders (tenant_id bigint, id bigint, total numeric, PRIMARY KEY (tenant_id, id));
SELECT create_distributed_table('orders', 'tenant_id');
SELECT create_reference_table('countries');
```

`ziroctl pg add-shard events` adds a worker group and starts Citus's online shard rebalance, which moves shards with
logical replication without blocking writes. Progress shows in `ziroctl pg status events`.

The Citus image is not bundled: pass an image pinned by digest, as with every image on the cluster (see
[Clustering](clustering.md#image-policy)). Choosing the distribution key is the user's job; a good key has many
distinct values and appears in most queries (tenant, user or device id).

## Backups and recovery

Backups use [pgBackRest](https://pgbackrest.org) and go to S3-compatible object storage: AWS S3, Cloudflare R2,
Backblaze B2, MinIO, or anything else that speaks the S3 API.

```sh
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...
ziroctl pg backup enable shop --s3-endpoint s3.eu-west-1.amazonaws.com --bucket acme-db --region eu-west-1
ziroctl pg backup passphrase shop     # store it in your password manager: a restore needs it
ziroctl pg backups shop               # backups, and the window a restore can target
ziroctl pg backup now shop --type full
ziroctl pg restore shop-copy --from shop --to 2026-11-03T08:00:00Z
```

### What happens when backups are on

- **WAL archiving.** Every member archives its WAL to the repository as it is written. The push is asynchronous,
  through a spool on the data volume, and happens at least once a minute while there are writes
  (`archive_timeout`).
- **Scheduled backups.** The controller takes the backups the schedule asks for, on the group's primary. The
  schedule is recorded in the cluster state, so it survives a master change.

  | Type | Default schedule (UTC) | What it copies |
  | --- | --- | --- |
  | Full | `0 1 * * 0`, Sundays at 01:00 | everything |
  | Differential | `0 1 * * 1-6`, the other days at 01:00 | changes since the last full backup |
  | Incremental | `30 * * * *`, every hour | changes since the last backup |

  Change the schedule with `--full`, `--diff` and `--incr` (five-field cron expressions). The first full backup
  starts as soon as the repository is ready.
- **Compression and encryption.** Backups are compressed with zstd and encrypted with AES-256. The passphrase is
  generated for each cluster.
- **Retention.** pgBackRest keeps `--retention` full backups (4 by default), with the differentials, incrementals
  and WAL they need, and expires the rest after each backup.
- **Replica catch-up.** A replica whose slot no longer has the WAL it needs fetches it from the repository, so it
  catches up instead of being rebuilt.
- **Image.** The members move to the Ziro Postgres image with pgBackRest (`ghcr.io/ziro-os/postgres:<version>-pgbackrest`,
  built by `.github/workflows/pg-images.yml` and pinned by digest), restarting one at a time. Pass `--image` to use
  your own image with pgBackRest, pinned by digest.

### Keys and the passphrase

- **Keys.** The repository's keys come from `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, never from the command
  line. They are kept in the sealed cluster secret `pg-<name>-backup` with the passphrase, and only the members
  receive them.
- **The passphrase.** The API never serves the passphrase; `ziroctl pg backup passphrase` prints it on the master.
  **Keep a copy outside the cluster.** If every node is lost, the bucket is all that is left, and without the
  passphrase it cannot be read.
- **Changing the configuration.** `pg backup enable` again changes the bucket, schedule or retention and keeps the
  passphrase.
- **Turning backups off.** `pg backup disable` stops archiving and the schedule. The backups stay in the bucket.

### Where the backups are

The repository for a cluster is `s3://<bucket>/<path>/<name>`, with `--path` defaulting to `/ziro`. Each group is a
stanza in it: `main` for a plain cluster, `coord` and `w1`, `w2` and so on for Citus.

### Restore

`ziroctl pg restore` always creates a new cluster, so the cluster being restored keeps running until you move the
apps:

```sh
ziroctl pg restore shop2 --from shop                              # the latest state
ziroctl pg restore shop2 --from shop --to 2026-11-03T08:00:00Z    # the state at that moment (UTC)
```

How a restore runs:

1. The new cluster's first primary restores the newest backup taken before the target.
2. It replays the archived WAL up to the target and is promoted on a new timeline.
3. Its replicas then copy it.

The target can be any moment from the end of the oldest kept backup up to the last archived WAL, as shown by
`pg backups`. Postgres stops just before the first commit after the target, so a transaction committed at the
target itself is not included. The new cluster writes its own backups to `<path>/<new name>` in the same bucket.
Point the apps at `<new name>-rw` (or rename them over) once it is healthy.

### Disaster recovery: every node is lost

The bucket and the passphrase are all you need. On a new Ziro cluster:

```sh
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... PG_BACKUP_PASSPHRASE=...
ziroctl pg restore shop --s3-endpoint s3.eu-west-1.amazonaws.com --bucket acme-db --region eu-west-1 \
  --path /ziro/shop --version 17
ziroctl pg status shop                                  # wait for the primary, then the replicas
ziroctl pg credentials shop                             # new passwords: update the apps
```

Give `--database` and `--user` when they were not `app`. The restored cluster backs itself up to
`/ziro/shop/shop` in the same bucket, so the old backups stay untouched.

### Recovery point and recovery time

- **RPO.** Up to about a minute of commits (`archive_timeout`), plus whatever was still in the archive spool.
  Within the cluster, a failover loses nothing.
- **RTO.** The restore downloads the newest backup and replays the WAL archived since it. With an hourly
  incremental, that is at most an hour of WAL plus the size of the database at the bucket's throughput. Practise
  it: restore into a scratch cluster now and then, and delete it afterwards.

## Monitoring

`ziroctl pg status shop` lists the members with role, node, state, timeline, lag and the latest events, and the
reasons a group is not healthy.

`ziroctl pg overview` shows every cluster on one screen, the ones that need attention first:

```text
NAME             PG  HEALTH    PRIMARY      READY   LAG      CONN  DISK  BACKUP      ALERTS
billing          17  degraded  m2@n3        2/3     1.2s     41%   83%   3 hours ago 1
shop             17  healthy   m1@n1        3/3     0s       12%   40%   47 minutes ago 0

Needs attention:
  billing: m3 is catching up (1200ms behind)
  billing: a data volume is 83% full
```

The health of a cluster is one of four values:

| Health | Meaning |
| --- | --- |
| `healthy` | every member is ready and nothing needs attention |
| `degraded` | it serves, but something needs attention |
| `down` | a group has no primary that answers |
| `paused` | the controller is paused |

"Needs attention" covers:

- the reasons from `pg status`;
- members waiting for the maintenance window;
- missing or old backups;
- data volumes 80 % full or more;
- 90 % of the connections in use.

`--json` prints the same as `GET /api/v1/pg-overview`.

`ziroctl pg top` is the same view, live in the terminal and refreshed every 2 seconds, with transactions per second.
Enter opens a cluster: its members, what needs attention and the latest events.

| Key | Action |
| --- | --- |
| `↑`/`↓` or `j`/`k` | select |
| `Enter`, `Esc` | open a cluster, back to the fleet |
| `s` | switchover (to the selected replica, or the one furthest ahead) |
| `r` | rebuild the selected replica |
| `a` | add a replica |
| `b` | take an incremental backup now |
| `p` | pause or resume the controller |
| `?`, `q` | help, quit |

Every action asks for confirmation. Without a terminal, `pg top` prints `pg overview` once.

### Dashboard

The API server also serves a dashboard for the Postgres clusters, at `https://<master>:8443/ui/`. Sign in with an API
token:

```sh
ziroctl api token create dashboard --role operator
```

The token stays in that browser tab, in session storage, and is gone when the tab closes. The page calls the same
API as the CLI, so it can do no more than the token's role allows:

| Role | What the dashboard can do |
| --- | --- |
| viewer | look |
| operator | switchovers, backups, rolling restarts and pausing |
| admin | restores and configuration changes |

The pages:

- **Fleet:** every cluster's health, worst first, with what needs attention.
- **Overview** of a cluster: members, roles, lag and a topology view, with switchover (to a chosen replica),
  backup, rolling restart and pause.
- **Backups:** the backups and the recoverable window, and a restore wizard that copies the cluster at the latest
  state or a chosen moment into a new cluster.
- **Events:** the cluster's history, newest first.
- **Roles and databases:** what exists, and whether each is applied yet. Passwords are never shown.
- **Configuration:** the cluster file as JSON. Edit it, see the plan, apply it.

Every change asks for confirmation first. The page refreshes every 2 seconds, and holds off while you are editing
something.

The dashboard is plain HTML, CSS and JavaScript embedded in ziroctl. Nothing is loaded from anywhere else, and a
Content-Security-Policy allows only its own files and the API. Its files are the only public route besides
`/api/v1/health`, and they hold no data. `tests/ui/dashboard-smoke.js` drives it in Chromium against a fake API.

`ziroctl pg events shop` prints the cluster's history, oldest first: promotions, switchovers, repairs, rolling
changes, backups and alerts, with their severity. The last 200 events of each group are kept in cluster state, so
the history survives a master change. `--since 24h` limits it to a recent period, and `--follow` keeps printing new
events. The API serves it at `GET /api/v1/pg/{name}/events?since=<RFC 3339>`.

The master's
`/metrics` has, per cluster, group and member:

- roles: `ziro_pg_members`, `ziro_pg_primary`, `ziro_pg_epoch`;
- replication: `ziro_pg_replication_lag_milliseconds`;
- load: `ziro_pg_connections` and `ziro_pg_max_connections`, `ziro_pg_commits_total` (use `rate()` for
  transactions per second);
- health: `ziro_pg_xid_age` and `ziro_pg_disk_used_percent`;
- backups: `ziro_pg_backup_last_seconds` (by type), `ziro_pg_backup_repository_bytes`,
  `ziro_pg_archive_failed_total` and `ziro_pg_archive_last_seconds`.

Alerts of category `database` fire on a promotion, when no safe promotion exists, when a command to a member
fails, when a switchover is aborted, when no node is free for another replica, when a member's data volume is 80 %
or 90 % full, when 90 % of the connections are in use, when transaction ID wraparound gets near (the oldest
unfrozen transaction is 1.5 billion transactions old), when WAL archiving fails, and when no backup has finished
for longer than the schedule allows.

## Security

- **TLS.** Every new cluster has its own CA. Members replicate with `sslmode=verify-ca`, so only a member of this
  cluster can serve as its primary, and Citus nodes connect to each other the same way. Clients can check the
  server with the CA: `ziroctl pg credentials shop --ca > shop-ca.crt`, then
  `sslmode=verify-full sslrootcert=shop-ca.crt` against `shop-rw.cluster.ziro`. The connection strings
  `ziroctl pg credentials` prints use `sslmode=require`.
- **Who may log in.** The superuser `postgres` logs in over the container's local socket only, which is what the
  agent uses. Over the network it is refused, except between Citus nodes. Replication has its own role.
- **Passwords.** Passwords are generated, stored in sealed cluster secrets and checked with SCRAM-SHA-256.
  `ziroctl pg rotate-password shop` changes the application user's password (`--role replicator` or `postgres`
  for the others). The primary receives only the new password's SCRAM verifier, never the password itself. The
  members then restart on the new secret one at a time, and open sessions stay open.
- **Exposure.** `pg expose` requires `--allow`.

## Removing a cluster

```sh
ziroctl pg rm shop                    # stops the members and keeps the data and credentials
ziroctl pg rm shop --purge --yes      # also deletes the data on every node and the credentials
```

## Changes in behavior

- `ziroctl pg create` makes two replicas by default (synchronous, no acknowledged write lost on failover), and a
  pooler.
- The members' tuning changed (`pg_stat_statements`, `auto_explain`, `jit` off, lz4 WAL compression,
  `max_worker_processes` fixed at 32): existing clusters roll onto it once, one member at a time.
- `pg expose` requires `--allow`, and `pg rm --purge` requires `--yes`.
- The failover grace is 36 s (was 30 s), so a primary's lease always ends first.
- New clusters use TLS, and the superuser no longer logs in over the network.
- A ziroctl upgrade that changes the members' entry script rolls out one member at a time, with a switchover before
  the primary restarts, instead of restarting every member together.

## Limits

- Known limitation: a major version upgrade (17 to 18) is a dump and restore into a new cluster; `pg upgrade` refuses
  it.
- Known limitation: clusters created before the pooler have none until `ziroctl pg pool <name> --enable`.
- Known limitation: backups run on the primary. Backing up from a standby needs pgBackRest's TLS server, which is not
  set up.
- Known limitation: a sharded (Citus) cluster is backed up group by group, but `pg restore` refuses it: there is no
  common restore point across the groups yet.
- Known limitation: `pgbackrest verify` is not scheduled. Restore into a scratch cluster to check the backups.
- Known limitation: Citus reads from worker replicas (`citus.use_secondary_nodes`) are not wired in; the `-ro` name of
  a sharded cluster reads from the coordinator's replicas.
- Known limitation: a worker group cannot be removed yet; `add-shard` is one way.
- Known limitation: roles connect directly, not through the pooler: its user list has only the application user.
- Known limitation: `pg rotate-password` covers the application user, `replicator` and `postgres`, not the roles
  from `pg role`. To change a role's password, remove the role and add it again.
- Known limitation: a sharded cluster manages only its own database (`pg db` with another name is refused).
- Known limitation: a cluster created before TLS keeps running without it. Members are probed by running `psql`
  in their containers, and orders are carried out the same way; the lease watchdog covers the case where that
  channel hangs.
- Failover needs the leader master and a recent probe from the node of the replica; with three or more masters a
  master outage does not pause it (see [Clustering](clustering.md#high-availability-control-plane)).
- The failover logic is tested by simulation of cluster state and probes, and the entry script against a real
  PostgreSQL (`tests/pg/entry-test.sh`); the QEMU cluster test `tests/qemu/pg-cluster.py` covers the whole path.
