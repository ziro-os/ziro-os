# Ziro-OS Clustering

A Ziro-OS cluster is one **master** plus any number of **workers**. The master also runs workloads.
Everything is built into `ziroctl` (Go standard library only). There is no etcd and no extra daemon to install.
Nodes are joined by an encrypted **WireGuard mesh**, and apps find each other as `<app>.cluster.ziro`.

## Quick start

```sh
# On the master
ziroctl cluster init --advertise 10.0.0.10
#   prints: ZIRO_CLUSTER_TOKEN=<token> ziroctl cluster join 10.0.0.10:7443 --ca-hash sha256:<hash>

# On each worker (the token comes from the environment or --token-file, never argv)
ZIRO_CLUSTER_TOKEN=<token> ziroctl cluster join 10.0.0.10:7443 --ca-hash sha256:<hash>

# On the master
ziroctl cluster secret set db-creds PASSWORD=s3cret
ziroctl cluster deploy --name web --image nginx:alpine --replicas 3 --port 8080:80 -e MODE=prod
ziroctl cluster deploy --name api --image ghcr.io/acme/api:1.4 --port 9000:9000 --mesh-only \
    --secret db-creds --arg serve --arg --verbose
ziroctl cluster services           # NAME REV IMAGE PORT STATUS
ziroctl cluster endpoints          # web.cluster.ziro:8080 -> 10.200.0.1, 10.200.0.2
```

The join token expires after 24 hours (`--token-ttl`, `0` = never). Print the join command again with
`ziroctl cluster token`, and replace the token with `ziroctl cluster token rotate [--ttl 1h]`.

## Day-2 operations

| Task | Command |
|---|---|
| Change only some settings (other flags keep their values) | `ziroctl cluster deploy --name web --image nginx:1.27-alpine` or `-e KEY=` to unset |
| Declarative deploy (one app or a list, JSON) | `ziroctl cluster apply -f apps.json` |
| Scale | `ziroctl cluster scale web 5` |
| Roll back to the previous revision (last 5 kept) | `ziroctl cluster rollback web` |
| Maintenance | `ziroctl cluster node cordon\|uncordon\|drain <node>` |
| Remove a dead worker and revoke its token | `ziroctl cluster node rm <node>` |
| Secrets (names and keys are listed, never values) | `ziroctl cluster secret set\|rm\|ls` |
| Network policy: who may reach an app over the mesh | `ziroctl cluster deploy --name api --allow-from web,worker` (`'*'` = any app), `cluster policy ls`, `cluster policy default deny\|allow` |
| Expose apps over HTTP(S) with TLS, rate limits and IP allowlists | `ziroctl gateway node enable <node>`, `gateway route add <name> --host … --app …`; see [gateway.md](gateway.md) |
| Machine-readable output | add `--json` to `status`, `nodes`, `services`, `endpoints`, `secret ls`, `policy ls` |

An `apps.json` manifest uses the same fields as the API:

```json
[{"name": "web", "image": "nginx:alpine", "replicas": 3, "port": "8080:80", "env": {"MODE": "prod"}},
 {"name": "api", "image": "ghcr.io/acme/api:1.4", "replicas": 2, "port": "9000:9000", "mesh_only": true,
  "secrets": ["db-creds"], "args": ["serve"], "allow_from": ["web"]}]
```

## How it works

| Piece | Runs on | Service | What it does |
|---|---|---|---|
| Control plane | master | `cluster-master` (`ziroctl cluster serve`, TLS :7443) | Join, heartbeat, leave, scheduling. Owns `/etc/ziro/cluster/state.json` (+ `secrets.json`). |
| Agent | every node | `cluster-agent` (`ziroctl cluster agent`) | Heartbeat every 10s. Converges its containers with nerdctl, and the `ziro0` mesh and `/etc/hosts` block. |

Both services use `restart=always`: ziro-init restarts them with a crash-loop backoff.

- **Scheduling:**
  - Replicas stay where they are while their node is Ready.
  - New replicas go to the least-loaded Ready node that isn't cordoned.
  - A host port (e.g. `8080/tcp`) is held by one replica per node, across **all** apps.
  - When a node joins or is uncordoned, one replica at a time moves onto it. Only apps with at least two replicas that are fully running move, so a move never takes an app down.
- **Rolling updates:**
  - Every spec change (image, port, env, args, secrets) creates a new **revision**.
  - Replicas move to it one at a time: the next one only after the updated replica reports running.
  - If the new revision fails to start (bad image, port clash), the rollout **pauses**. The error shows in `cluster services`, the remaining replicas keep serving, and `cluster rollback` restores the previous revision.
- **Failure handling:**
  - Agents report start failures in their heartbeat. A replica that fails 3 times in a row moves to another node.
  - A node that misses heartbeats for 30s becomes **NotReady** and its replicas are rescheduled. After 24h it is removed.
  - If the master is unreachable, agents keep existing workloads running.
  - Image pulls run separately from heartbeats, with a 10-minute timeout, so slow pulls never make a node look dead.
- **Mesh and discovery:**
  - Each node has a WireGuard key and a mesh IP from `--mesh-cidr` (default `10.200.0.0/16`, udp/51821).
  - The master distributes peers in heartbeat replies.
  - Agents keep an `<app>.cluster.ziro` block in `/etc/hosts` that lists only nodes with a running replica, and cluster containers get the same entries (`--add-host`, refreshed when the container is recreated).
  - `--mesh-only` publishes a port only on the mesh IP.

## Network policy

- New clusters start with `policy default deny`. Traffic that arrives over the mesh reaches an app's port only
  from nodes that run an app named in that app's `allow_from`. Traffic from anywhere else on `ziro0` is dropped;
  ICMP is still allowed.
- Changing `allow_from` doesn't create a new revision or restart containers. Agents apply it within one heartbeat.
- On the pod network (the default for new clusters), rules are per container: an app is reachable only from the
  pod IPs of allowed apps' replicas, on any node, including the same node. Without the pod network, rules are per
  node, because containers are masqueraded to their node's mesh IP.
- Public (non `--mesh-only`) ports are still governed by the host firewall.
- Clusters created before policies existed stay on `allow`. Switch with `ziroctl cluster policy default deny`
  after adding `allow_from` to apps that talk to each other. `cluster policy ls` shows the admitted node IPs.
- Enforcement lives in the agent's `inet ziro_cluster` nftables table. If it can't be applied, the node reports
  `MeshError` in `cluster nodes` and the mesh isn't configured, so the node fails closed.

## Security model

- **Join:**
  - The worker pins the SHA-256 of the master's TLS certificate (`--ca-hash`, same idea as kubeadm's `--discovery-token-ca-cert-hash`) and presents the join token.
  - Both checks are constant-time, and tokens expire.
  - Join is rate-limited per IP, and node descriptions are validated and sanitized.
- **Node identity:** each node gets its own random 256-bit token. The master stores only its SHA-256. `leave` and `node rm` revoke it.
- **Secrets:**
  - Stored `0600` on the master, sent only over the pinned TLS channel to the nodes that run the app, and written to `0600` env files on tmpfs (`/run/ziro/cluster/secrets`).
  - They never appear in argv or `ps`.
  - Backups leave them out unless you pass `--include-secrets`.
- **Exposure:**
  - `cluster init`/`join` opens tcp/7443 and udp/51821 and trusts `ziro0`, whose peers are authenticated by their WireGuard keys. The network policy then narrows that trust. A firewall the admin disabled stays disabled.
  - The admin REST API stays on `127.0.0.1:8443`.
  - `/api/v1/cluster` returns a redacted view with no tokens or secrets.
- **Input:** app names, images, ports, env keys and secrets are validated, and images are passed after `--`.

## Pod network

New clusters give every replica its own routed IP. `cluster init --pod-cidr` defaults to `10.201.0.0/16`;
`--pod-cidr none` turns this off and keeps host-port networking.

```sh
ziroctl cluster network status          # node /24s and replica IPs
ziroctl cluster network enable          # migrate an existing cluster (apps roll over one replica at a time)
```

- Each node gets a /24, and the master assigns each replica an IP in its node's /24 when it places the replica.
  So policy and DNS know the address before the container starts. A replica keeps its IP while it stays on a
  node (rollouts replace the container in place) and gets a new one when it moves.
- Containers attach with the CNI `ptp` plugin (a veth plus a /32 route each, MTU 1420). Every packet between
  containers, even on the same node, is routed through the host and policed by nftables.
- Nodes route each other's /24 over WireGuard. Only traffic leaving the cluster is masqueraded, so a
  destination sees the real pod IP.
- **DNS:** each node answers `<app>.cluster.ziro` on its `.1` address with the IPs of running replicas (TTL 5s).
  Containers get it through `--dns`/`--dns-search cluster.ziro`, so plain `http://web` works too. Other names
  are relayed to the node's own resolvers. It only answers the node's own containers. Endpoint changes are
  live; containers are no longer restarted to see them.
- **Ports:** inside the cluster, apps talk to the **container** port on pod IPs (`http://web.cluster.ziro`,
  not `:8080`). `--port` host ports still publish apps outside the cluster, and the gateway goes straight to
  the pod IP and container port. On nodes, `<app>.cluster.ziro` in `/etc/hosts` also lists pod IPs.
- WireGuard remote peers get the pod network in their `AllowedIPs`.

## Limits (by design, for now)

- There is a single master. If it is down, running workloads continue, but nothing new is scheduled.
- Placement counts replicas, not CPU or memory.
- Without the pod network, discovery uses hosts entries: a container sees new endpoints only when it is recreated.
- IPv4 only; one pod /24 per node (253 replicas).
