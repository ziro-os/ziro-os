# RFC 0005: Postgres clusters

- **Status:** Draft
- **Author:** @sombochea
- **Pull request:** #

## Summary

`ziroctl pg` creates and operates PostgreSQL clusters on a Ziro cluster: one primary and any number of streaming
replicas, automatic failover with fencing, planned switchover, replicas added and removed without downtime, and
horizontal sharding with Citus for multiple writers. A controller on the cluster master reconciles a declared
`PGCluster` into ordinary cluster apps, one per member, and keeps the roles in cluster state.

## Motivation

The catalog app `postgres` is a single instance. Scaling it creates independent, empty databases (every replica
keeps its own node-local data and runs its own `initdb`), and a node failure moves the replica to a node with an
empty data directory. `mysql-cluster` shows that a replicated database can run as plain cluster apps, but it leans
on the database's own consensus (Group Replication). PostgreSQL has none: streaming replication needs something
outside the database to choose a primary, fence the old one, and point clients at the new one. The cluster has the
parts to do that (Raft-replicated state, a leader-only controller loop, pod DNS, TCP routes in the gateway) but not
the glue: a replica cannot be pinned to the node that holds its data, a container cannot be given configuration
files, the master cannot see inside a container, and DNS names cannot follow a role.

## Design

### Resources

```text
PGCluster   name, version, settings, epoch, groups[]
PGGroup     name, members[], sync policy        (a plain cluster has one group; Citus has a coordinator
                                                 group and one group per shard)
PGMember    id, node, role, probe, command      (one container, one data directory, one node)
```

`PGCluster` is stored in `ClusterState.PG`, replicated by Raft like the rest of the state. Each `PGMember` is
rendered into a one-replica `ClusteredApp` named `pgc-<cluster>-<group>-m<n>`:

- **Pinned.** `ClusteredApp.Node` fixes the node, and the member is sticky: it waits for its node rather than
  starting empty elsewhere. Members of one group are spread over different nodes.
- **Configured.** `ClusteredApp.ConfigFiles` are written by the agent into a read-only directory mounted at
  `/etc/ziro-config`: the entry script and `postgresql.conf` settings. They are part of the spec hash. A separate
  `Dynamic` map (the member's current role and epoch) is rewritten by the agent without restarting the container.
- **Secrets.** Passwords are a cluster secret `pg-<cluster>`, delivered as an env file like every app secret.

### Roles and the controller

The agent probes each member container every five seconds with a fixed query (recovery state, WAL position,
timeline, replay lag) and reports the result in its heartbeat. The controller, a leader-only pass beside the
healer, decides:

- **Failover.** The primary is failed when it has not answered for the grace period (15 s). The controller promotes
  the reachable replica with the highest replayed LSN, but only when enough replicas are reachable to be sure it
  has every committed write: with quorum synchronous replication (`ANY k (*)`) that is at least `n - k + 1` of `n`
  replicas. It bumps the epoch, orders `promote`, and when the member reports the new timeline it marks it primary
  and the old primary `fenced`. Asynchronous clusters (one replica, no `--sync`) may lose the replication lag; the
  controller refuses to promote beyond a configured lag unless forced.
- **Fencing.** A fenced member must not accept writes. Quorum commit already stops an isolated primary from
  committing. In addition, a restarting member reads its role from the dynamic role file and, if it is not the
  primary, rewinds (`pg_rewind`, falling back to a new base backup) and follows the current primary. A member that
  believes it is primary starts only if the role-following DNS name does not point at another live primary.
- **Switchover.** `pg switchover` makes the primary read-only, waits for the target to catch up, promotes it, and
  turns the former primary into a replica. Writes pause for seconds; nothing is lost.
- **Replicas.** `pg add-replica` renders a new member. Its entry script takes a base backup from the primary (or a
  chosen replica) with `pg_basebackup -X stream -C -S <slot>`, so the primary's service is not interrupted; the
  `ANY k (*)` setting needs no change on the primary. A replica joins the read-only name when its lag is under a
  threshold. Removal takes it out of that name first, drops its slot, then deletes its data.
- **Updates.** Replicas are updated one at a time, then a switchover, then the former primary. Containers stop with
  a long grace period so Postgres shuts down cleanly.

The controller only acts on fresh data and does nothing while the cluster is partitioned (the healer's brake), so a
loss of contact with a node is not mistaken for the loss of a primary. All decisions are written to `ClusterState`,
so a new leader continues where the old one stopped; commands carry the epoch and are idempotent.

### Agent commands

The master cannot execute arbitrary commands. The heartbeat response carries `PGCommands` from a closed list, each
with an epoch: `promote`, `fence`, `unfence`, `checkpoint`, `drop-slot <name>`, and, for sharding, fixed Citus
statement templates. Arguments are validated (names against a strict pattern); the agent runs them in the member's
container with `nerdctl exec` and reports the result in the next heartbeat. Nothing outside the list can be run.

### Endpoints

Pod DNS answers role-following names computed from `ClusterState.PG`: `<cluster>-<group>-rw` is the primary,
`<cluster>-<group>-ro` the ready replicas (the primary when there are none). `<cluster>-rw` and `<cluster>-ro` alias the
default group (the only group, or the Citus coordinator). Replicas use the read-write name as their
`primary_conninfo`, so they follow a new primary by themselves. A connection pooler (PgBouncer as
ordinary stateless cluster apps) is a follow-up. `pg expose` creates gateway TCP routes with allow-lists.

### Sharding

A sharded cluster is a coordinator group plus worker groups, each with its own replicas, running the Citus
extension. The controller registers workers by their read-write DNS names, so a worker failover changes no Citus
metadata. It enables metadata sync so any node can take writes, and `pg add-shard` deploys a group, registers it
and starts Citus's non-blocking shard rebalance (logical replication). Durability inside a group comes from
streaming replication; Citus shard replication stays at 1. Users choose their distribution keys with
`create_distributed_table`.

### Commands and API

```sh
ziroctl pg create db --version 17 --replicas 2 [--shards 3 --citus-image <image>] [--memory 4Gi --cpus 2]
ziroctl pg ls | status db | credentials db
ziroctl pg add-replica db [--node N] [--from member]
ziroctl pg scale db --replicas 4
ziroctl pg rm-replica db <member>
ziroctl pg switchover db [--to member]
ziroctl pg expose db --port 5432 [--allow CIDR]
ziroctl pg add-shard db
ziroctl pg rm db [--purge]
```

API: `GET /api/v1/pg`, `GET|DELETE /api/v1/pg/{name}`, `POST /api/v1/pg` (admin), `POST
/api/v1/pg/{name}/{action}` for `scale`, `add-replica`, `rm-replica`, `switchover`, `add-shard` (operator).
Credentials are never served over the API.

## Security

- The controller and agent commands are the only new way to act inside a container, and they are a closed list with
  validated arguments; no shell string or SQL from a client reaches a container.
- Passwords are cluster secrets (sealed, replicated, delivered as env files). Replication uses its own role over
  scram-sha-256, allowed only from the pod CIDR. The superuser socket is reachable only inside the container.
- Pod network policy applies: only the cluster's own members and the apps named with `--allow-from` can
  reach the ports. The gateway route is opt-in with an allow-list.
- A compromised replica can read what replication sends it (everything). It cannot promote itself: roles come from
  the master and commands carry the epoch.

## Compatibility

All new fields are optional. Existing apps and the `postgres` catalog app are unchanged. Clusters without `pg`
clusters carry an empty `ClusterState.PG`. Agents that predate the probe channel simply never report probes; the
controller treats such members as unmanageable and does nothing to them.

## Alternatives

- **A catalog app (`postgres-cluster`) like `mysql-cluster`.** Without an external decision-maker there is no safe
  failover for PostgreSQL, and the platform lacks node pinning, configuration files and role-aware names either way.
- **Patroni or Stolon inside the containers.** They need a separate consensus store (etcd or Consul) and an extra
  image per member; the cluster already has Raft, a leader and DNS.
- **A routing proxy for sharding.** Hash routing in ziroctl is a large amount of new code and cannot do cross-shard
  queries or transactions; Citus is mature and provides online rebalancing.
- **An operator in a separate process.** The controller needs the Raft-replicated state and the leader loop; a
  second process would duplicate both.
