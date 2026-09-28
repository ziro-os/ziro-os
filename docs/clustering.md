# Ziro-OS Clustering

A Ziro-OS cluster is one **master** plus any number of **workers**. The master also runs workloads.
Everything is built into `ziroctl` (Go standard library only). There is no etcd and no extra daemon to install.

## Quick start

```sh
# On the master
ziroctl cluster init --advertise 10.0.0.10
#   prints: ziroctl cluster join 10.0.0.10:7443 --token <token> --ca-hash sha256:<hash>

# On each worker
ziroctl cluster join 10.0.0.10:7443 --token <token> --ca-hash sha256:<hash>

# On the master
ziroctl cluster deploy --name web --image nginx:alpine --replicas 3 --port 8080:80 -e MODE=prod
ziroctl cluster services      # web  nginx:alpine  8080:80  3/3 running
ziroctl cluster nodes
ziroctl cluster remove web
```

Run `ziroctl cluster token` on the master to print the join command again.

## How it works

| Piece | Runs on | Service | What it does |
|---|---|---|---|
| Control plane | master | `cluster-master` (`ziroctl cluster serve`, TLS :7443) | Handles join, heartbeat and leave. Owns `/etc/ziro/cluster/state.json`. |
| Agent | every node | `cluster-agent` (`ziroctl cluster agent`) | Sends a heartbeat every 10s, receives its assignments, and converges local containers with nerdctl. |

- **Scheduling:**
  - Replicas stay on Ready nodes, so nothing moves without a reason.
  - A new or orphaned replica goes to the Ready node with the fewest replicas.
  - An app with `--port` runs at most one replica per node. Extra replicas show as *pending* until another node joins.
- **Failure handling:**
  - A node that misses heartbeats for 30s becomes **NotReady**, and its replicas are rescheduled.
  - When it comes back, its agent removes the containers it no longer owns.
  - If the master is unreachable, agents **keep existing workloads running**.
- **Updates:** the container name includes a hash of the image, port and env (`zc-<app>-<n>-<hash>`). Changing any of them replaces the container.
- **State:** the master keeps its state in a JSON file, guarded by `flock` and written atomically.

## Security model

- **Join:** the worker pins the SHA-256 of the master's TLS certificate (`--ca-hash`, same idea as kubeadm's `--discovery-token-ca-cert-hash`) and presents the 128-bit join token. Both checks are constant-time. Join is rate-limited per IP.
- **Node identity:** each node gets its own random 256-bit token. The master stores only its SHA-256. After `leave`, the token is revoked.
- **Exposure:** only port 7443 is exposed, and `cluster init` opens it in the firewall. The admin REST API stays on `127.0.0.1:8443`. `/api/v1/cluster` returns a redacted view with no tokens.
- **Files:** everything under `/etc/ziro/cluster` is `0600`/`0700`, and container images are passed after `--`.

## Limits (by design, for now)

- There is a single master. If it is down, running workloads continue, but nothing new is scheduled.
- Placement counts replicas, not CPU or memory, and there is no rebalancing when a node joins.
- There is no cross-node service discovery or overlay network. Expose apps with host ports, or pair the cluster with `ziroctl wireguard`.
