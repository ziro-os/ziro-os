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

To reach the database from outside the cluster, publish it through the [gateway](gateway.md):

```sh
ziroctl pg expose shop --port 5432 --allow 203.0.113.0/24
ziroctl pg expose shop --port 5433 --ro
```

Passwords are cluster secrets; they are shown only by `ziroctl pg credentials` on the master and are never served
over the API.

## Replication and durability

| Setting | Behavior |
| --- | --- |
| `--sync quorum` (default) | With two or more replicas, a commit waits for one replica (`ANY 1 (*)`). A failover loses no acknowledged write, and an isolated old primary cannot commit. With one replica replication is asynchronous, because waiting for the only replica would stop writes when it is down. |
| `--sync off` | Always asynchronous: the fastest commits; a failover can lose the writes the replica had not received. |

Every replica has a physical replication slot on the primary, and `max_slot_wal_keep_size` keeps a replica that is
gone for good from filling the primary's disk. A replica that falls too far behind is rebuilt from a new base
backup.

Memory and CPU limits tune `shared_buffers`, `effective_cache_size`, `work_mem`, WAL sizes and the worker settings.
Data checksums and `scram-sha-256` are on.

## Failover

The agent on each node checks every member every 5 seconds. The controller on the cluster leader declares the
primary failed when its node is down or it has not answered for 30 seconds, and then:

1. picks the replica that has replayed the most WAL, within 16 MiB of the failed primary's last known position (a
   further-behind replica is promoted only by an operator, since that can lose writes);
2. refuses to promote unless the replicas it can reach could have received every synchronous commit, so a minority
   cannot promote itself next to a live primary (with `--sync quorum`);
3. raises the cluster epoch, orders the promotion, and moves `-rw` to the new primary when it confirms;
4. fences the old primary: when it returns, its entry script finds another primary behind `-rw`, refuses to serve,
   and rejoins as a replica with `pg_rewind`, or from a new base backup when the rewind is not possible.

The controller does nothing while the cluster is partitioned or when probe data is stale. `ziroctl pg pause shop`
stops it from changing roles at all (for maintenance) and `ziroctl pg resume shop` brings it back. Every promotion
is an alert in the category `database` and is listed in `ziroctl pg status`.

### Planned switchover

```sh
ziroctl pg switchover shop              # to the replica furthest ahead
ziroctl pg switchover shop --to m3
```

The primary is made read-only, the target catches up and is promoted, `-rw` moves, and the old primary becomes a
replica. Writes pause for a few seconds and no data is lost. Use it before maintenance on the primary's node.

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

## Monitoring

`ziroctl pg status shop` lists the members with role, node, state, timeline, lag and recent events. The master's
`/metrics` has `ziro_pg_members`, `ziro_pg_primary`, `ziro_pg_epoch` and `ziro_pg_replication_lag_milliseconds` per
cluster, group and member. Alerts of category `database` fire on a promotion, when no safe promotion exists, when
a command to a member fails, when a switchover is aborted and when no node is free for another replica.

## Removing a cluster

```sh
ziroctl pg rm shop              # stops the members and keeps the data and credentials
ziroctl pg rm shop --purge      # also deletes the data on every node and the credentials
```

## Limits

- Known limitation: there is no connection pooler yet; keep `max_connections` in mind or run PgBouncer as a cluster app
  in front of `-rw` and `-ro`.
- Known limitation: no point-in-time recovery or WAL archiving yet; back up with `pg_dump` or the [backup](backup.md)
  tools until it lands.
- Known limitation: Citus reads from worker replicas (`citus.use_secondary_nodes`) are not wired in; the `-ro` name of
  a sharded cluster reads from the coordinator's replicas.
- Known limitation: a worker group cannot be removed yet; `add-shard` is one way.
- Failover needs the leader master and a recent probe from the node of the replica; with three or more masters a
  master outage does not pause it (see [Clustering](clustering.md#high-availability-control-plane)).
- The failover logic is tested by simulation of cluster state and probes, and the entry script against a real
  PostgreSQL (`tests/pg/entry-test.sh`); the QEMU cluster test `tests/qemu/pg-cluster.py` covers the whole path.
