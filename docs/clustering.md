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
| Control plane | every master | `cluster-master` (`ziroctl cluster serve`, TLS :7443, Raft :7444) | Join, heartbeat, leave, scheduling (the Raft leader). Each master holds the replicated state in `/etc/ziro/cluster/` (`state.json`, `secrets.json`, `raft/`). |
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
  - The joiner pins the SHA-256 of the **cluster CA** (`--ca-hash`, same idea as kubeadm's `--discovery-token-ca-cert-hash`) and presents the join token. Any master whose certificate chains to that CA is trusted, so the pin survives failovers and certificate renewals.
  - Both checks are constant-time, and tokens expire.
  - Join is rate-limited per IP, and node descriptions are validated and sanitized.
- **Node identity:** each node gets its own random 256-bit token. The master stores only its SHA-256. `leave` and `node rm` revoke it.
- **Secrets:**
  - They are sealed at rest with a cluster data key (AES-256-GCM), in the Raft log, its snapshots and every
    master's files (`sealed.bin`). See [Secrets at rest](#secrets-at-rest).
  - They are sent only over the pinned TLS channel to the nodes that run the app, and written to `0600` env
    files on tmpfs (`/run/ziro/cluster/secrets`).
  - They never appear in argv or `ps`.
  - Backups contain only the sealed form; the data key is left out unless you pass `--include-secrets`.
- **Exposure:**
  - `cluster init`/`join` opens tcp/7443 and udp/51821 and trusts `ziro0`, whose peers are authenticated by their WireGuard keys. The network policy then narrows that trust. A firewall the admin disabled stays disabled.
  - The admin REST API stays on `127.0.0.1:8443`.
  - `/api/v1/cluster` returns a redacted view with no tokens or secrets.
- **Input:** app names, images, ports, env keys and secrets are validated, and images are passed after `--`.

## High availability (control plane)

Every master runs Raft; a single master is a one-voter group. Add masters for fault tolerance:

```sh
# On the first master: the join command also works for masters
ziroctl cluster token
# On two more hosts
ZIRO_CLUSTER_TOKEN=<token> ziroctl cluster join 10.0.0.10:7443 --ca-hash sha256:<hash> --control-plane
ziroctl cluster members                 # members, voters, leader, fault tolerance
ziroctl cluster member rm <master-id>   # remove a dead master (and revoke its node token)
```

| Masters | Survives |
|---|---|
| 1 | no master failure (workloads keep running; nothing is scheduled while it is down) |
| 3 | 1 master failure |
| 5 | 2 master failures |

- **What is replicated:** the desired state (apps, placement, node tokens, policy, routes, peers,
  pod network, secrets, the join token, the CA). It is committed as one Raft entry per change and
  written to `state.json`/`secrets.json` on every master.
- **What is not replicated:** liveness (last heartbeat, running containers). It changes every 10 s
  and lives in the leader's memory. A new leader gives every Ready node a full timeout (30 s) to
  report in before it reschedules anything.
- **Writes from any master:** `ziroctl` talks to its local `cluster-master` through a root-only
  unix socket (`/run/ziro/cluster-master.sock`). Followers forward to the leader over mutual TLS.
  Updates are compare-and-swap, so concurrent changes from different masters never overwrite each
  other.
- **Agents:** they know every master. A follower answers them with the leader's address (HTTP 421),
  and an unreachable master is skipped.
- **Joining:** a new master joins as a non-voter and asks to become a voter once it has caught up,
  so a joiner that never comes up cannot stall the cluster. Its master certificate is issued from
  a CSR, so its private key never leaves the host.
- **Upgrading from a single-master version:** automatic. On its first start, `cluster-master`
  imports the existing state into a new one-voter Raft group and creates the cluster CA. Agents
  still pinned to the old master certificate receive the CA in their next heartbeat and switch to
  it.
- **Ports:** tcp/7443 (cluster API) and tcp/7444 (Raft; mutual TLS with CA-signed master
  certificates only) on masters.

## Image policy

Control which images apps may run:

```sh
ziroctl cluster policy images --allow-registry ghcr.io/acme --allow-registry docker.io/library
ziroctl cluster policy images --require-signed --cosign-key cosign.pub     # repeat --cosign-key for several keys
ziroctl cluster policy images                                              # show
ziroctl cluster policy images --clear
```

- **Allowlist:** repository prefixes, matched on path boundaries (`ghcr.io/acme` does not match `ghcr.io/acmeevil`).
  An image outside it cannot be deployed.
- **Signatures:** with `--require-signed`, each deploy resolves the tag to a digest, verifies a cosign signature
  over that digest by one of the keys, and **pins the app to `image@sha256:<digest>`**. Every node then pulls
  exactly the verified content, with no tag drift between nodes and no gap between verifying and pulling.
- **Leader check:** the leader re-checks every changed image against the allowlist and the digest pin, whichever
  master proposed the change. Running apps are not touched when the policy changes; they are checked on their next
  deploy.
- **Supported signatures:** cosign key-based signatures in the classic layout (`cosign sign --key`,
  `sha256-<digest>.sig` tag) with ECDSA, Ed25519 or RSA keys. Keyless (Fulcio/Rekor) signatures and the
  OCI-referrers bundle format are not verified yet. Registries must allow anonymous pulls (Docker Hub, GHCR and
  most public registries do).

## Secrets at rest

The cluster secrets and the CA key are sealed with one random **cluster data key** (AES-256-GCM, bound to
the key's ID). The seal covers the Raft log, its snapshots and each master's files. Each master keeps its
own copy of that key, wrapped by a **key provider** it chooses:

| Provider | Protects against | Setup |
|---|---|---|
| `file` (default) | copied Raft data, backups | none: the key is a 0600 file, excluded from backups |
| `tpm` | the disk or its image leaving the machine | TPM 2.0 (bare metal, cloud vTPM) and the `custom` kernel flavor (the `alpine` kernel has no TPM drivers) |
| `command` | anything short of KMS or HSM compromise | two executables that call your KMS, Vault or HSM |

```sh
ziroctl cluster keys status                       # provider, and whether this master holds the key
ziroctl cluster keys provider tpm                 # re-wrap this master's copy (per master)
ziroctl cluster keys provider command --wrap /usr/local/bin/kms-wrap --unwrap /usr/local/bin/kms-unwrap
```

- **Command provider contract:** no shell. `wrap` reads the key (base64) on stdin and prints a wrapped blob.
  `unwrap` reads that blob and prints the key (base64). Every new wrapping is unwrapped and checked before it
  replaces the old one, and a provider that returns a different key is refused.
- **TPM provider:** the key is sealed under the owner-hierarchy SRK. Sessions are salted and encrypted, so
  the key never crosses the TPM bus in clear. It is not bound to PCRs, so kernel and OS upgrades keep
  working.
- **Distribution:** a master without the key fetches it from another master over mutual TLS (master
  certificates only; every fetch is audited) and wraps it with its own provider. A leader that cannot open
  the secrets hands leadership to a master that can, and it never hands out assignments without their
  secrets.
- **Upgrade:** automatic, and it waits for every master. The leader seals only once every master reports that
  it understands sealed state, so the order of a rolling upgrade does not matter. Each master then compacts
  its Raft log once, so no pre-seal plaintext stays in the log or snapshots. Freed database pages may still
  hold old bytes, as with any deleted file.
- **Rotating the data key:** `ziroctl cluster keys rotate`. The leader creates a new key, and every master
  fetches it and wraps it with its own provider. Only when **every** master holds it are the secrets re-sealed
  with it, so no master is ever left unable to open them. Each master then drops the old key and compacts its
  Raft log, so nothing sealed with the old key remains. `cluster keys status` shows which masters it is waiting
  for. Remove dead masters first (`cluster member rm`), because the rotation waits for every master.
- **Keep one master's key recoverable:** a KMS key, a working TPM, or a backup made with `--include-secrets`.
  Without the data key, sealed secrets cannot be recovered. Downgrading a master below this version after
  sealing is not supported.

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
- **DNS:** each node answers `<app>.cluster.ziro` on its `.1` address with the IPs of running replicas (TTL 5s),
  and `<index>.<app>.cluster.ziro` with one replica's IP as soon as it is placed (stable peer names for
  replicated databases; see [apps.md](apps.md)).
  Containers get it through `--dns`/`--dns-search cluster.ziro`, so plain `http://web` works too. Other names
  are relayed to the node's own resolvers. It only answers the node's own containers. Endpoint changes are
  live; containers are no longer restarted to see them.
- **Ports:** inside the cluster, apps talk to the **container** port on pod IPs (`http://web.cluster.ziro`,
  not `:8080`). `--port` host ports still publish apps outside the cluster, and the gateway goes straight to
  the pod IP and container port. On nodes, `<app>.cluster.ziro` in `/etc/hosts` also lists pod IPs.
- WireGuard remote peers get the pod network in their `AllowedIPs`.

## Nodes behind NAT (mesh "anywhere")

By default (`direct`) the mesh is kernel WireGuard. Every node must be able to reach every other node: one network, a VPN, or public addresses.

In **anywhere** mode, workers need only outbound internet, and **only the masters need a public address**.

```sh
ziroctl router relay enable eu-1 --public relay-eu.example.com:8443   # on a master (UDP 3478 + TLS 8443)
ziroctl cluster mesh mode anywhere
```

- **Same name, new engine.** Each node runs the mesh on the zirocd engine embedded in `cluster-agent`. The interface is still `ziro0`, with the same addresses, so app policy (`ziro_cluster` nft), the pod network, cluster DNS and gateway peers are unchanged.
- **Paths.** Nodes find each other the way router devices do: hole punching, PCP / NAT-PMP / UPnP port mapping, hard-NAT port probing, IPv6-first, roaming. Where no direct path exists, traffic goes through the relays, as UDP datagrams or over TLS where UDP is blocked. See [router.md](router.md#relays-and-nat-traversal).
- **Node certificates.** Each node gets one (OU `ziro-node`) through its heartbeat, valid 90 days and renewed automatically. It opens relay sessions only for the cluster mesh: it can never act as a master or a router device, and a relay never forwards between a node and a router device.
- **Soft state.** Endpoints, relays and NAT type travel in heartbeats as soft state. They never cause a Raft commit.
- **MTU.** The mesh MTU becomes 1280, so pod MTUs follow. Switching modes recreates pod-network containers one replica at a time; switch back with `ziroctl cluster mesh mode direct`.
- **Requirement.** Relays must be enabled first (the command refuses otherwise).

## Limits (by design, for now)

- With one master, a master outage stops scheduling (running workloads continue). Run 3 or 5 masters for HA.
- Placement counts replicas, not CPU or memory.
- Without the pod network, discovery uses hosts entries: a container sees new endpoints only when it is recreated.
- IPv4 only; one pod /24 per node (253 replicas).
- An app's `data` paths (`/var/lib/ziro/apps/<app>/<index>/` on the replica's node, `ZIRO_REPLICA` in the
  container) are node-local: a replica that moves starts empty. Use them for apps that replicate themselves.

## Cluster DNS records and egress control

- `ziroctl cluster dns add <name> <type> <value>` publishes a record that every node's smart DNS resolves.
- `ziroctl cluster deploy --egress <domains,CIDRs>` limits where an app's pods may connect outside the cluster.

See [dns.md](dns.md).
