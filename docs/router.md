# Ziro Router: global mesh networks

The router connects devices anywhere — laptops, CI runners, servers in other clouds, other Ziro clusters — into private networks, like a global network switch. Devices run **zirocd**, join with a key, get a stable address and name (`<device>.<network>.ziro`), and reach the peers the network's ACL allows over WireGuard.

| Piece | What it is | Status |
|---|---|---|
| Control plane | `ziroctl router`, served by `cluster-master` on every master (`/router/v1/*` on the cluster port, 7443) | shipped (R1) |
| Client | `zirocd` for Linux, macOS and Windows (amd64, arm64), signed releases with self-update | R2 |
| Relays + NAT traversal | `ziroctl router relay serve` (QUIC udp/443, TLS tcp/443, STUN udp/3478), hole punching | R3 |
| Kernel fast path, subnet routing on Ziro OS | `zirocd --dataplane kernel`, `ziroctl router join` | R4 |
| SSO | OIDC device-code login (`zirocd up --sso`) | R5 |

## Operator quick start

The router runs on the cluster masters. A standalone router is a one-master cluster (`ziroctl cluster init`). Masters must be reachable on the cluster port (tcp/7443) from wherever devices are. If devices dial a public name or a load balancer, set it once:

```sh
ziroctl router endpoints set router.example.com:7443
```

Create a network and a key:

```sh
ziroctl router network create office                 # a free /16 of 100.64.0.0/10 + a ULA /48
ziroctl router key create office --reusable --expiry 720h --tags laptop
# zr1_eyJyIjpbInJvdXRlci5leGFtcGxlLmNvbTo3NDQzIl0s...   (shown once)
```

On the device: `zirocd up --key zr1_...`

Other ways in:

- **Admin approval:** `ziroctl router network invite office` prints a key without a secret. Each device that uses it waits until `ziroctl router member approve office <device>`.
- **Ephemeral devices** (CI, autoscaling): `key create --ephemeral`. They are removed 10 minutes after going offline.

Every command takes `--json`. Every change is in the audit log (`ziroctl audit log`).

## Access control

Networks are **default deny**: devices see and reach nothing until a rule allows it. `network create --policy allow` starts with one rule that lets every device reach every device.

```yaml
# ziroctl router acl set office -f acl.yaml
groups:
  admins: [alice-laptop, bob-laptop]
rules:
  - src: [group:admins]
    dst: ["*:*"]
  - src: [tag:web]
    dst: [tag:db:5432]
    proto: tcp
  - src: [tag:ops]
    dst: ["10.200.0.0/16:22"]      # a subnet routed through a device
```

Selectors are `*`, `tag:<t>`, `group:<g>`, `member:<name>` or a CIDR. Destinations add ports: `*`, `443`, `8000-8100` or `22,443`. Unknown keys in the file are an error, so a typo can't silently drop a rule.

- `ziroctl router acl test office web-1 db-1 5432/tcp` answers from the same code the devices enforce.
- **Least visibility:** a device's netmap holds only the peers it may talk to (in either direction). Every other member's existence, keys and addresses stay hidden from it.
- Rules are enforced by the **receiving** device. WireGuard's cryptokey routing already guarantees that a packet's source address belongs to the peer that sent it.

**Subnet routes.** A device advertises subnets (`zirocd up --advertise-routes 10.200.0.0/16`). Nothing is routed until an admin runs `ziroctl router route approve office gw-1 10.200.0.0/16`. This is how a cluster mesh or a VPC joins a router network.

**Client version.** `ziroctl router network set office --client-version 1.0.21` pins the fleet's zirocd version (`latest` unpins it). Devices update to it through the signed release stream.

## How it works

```mermaid
sequenceDiagram
  participant D as zirocd
  participant F as any master
  participant L as leader (hub)
  D->>F: TLS 1.3, verify cluster CA (pin from key)
  D->>F: POST /register {join key, WG + disco keys, CSR}
  F->>L: relay over master mTLS
  L->>L: Raft commit member; sign device cert (30 days)
  L-->>D: cert, addresses
  D->>F: POST /map (device cert)
  F->>L: relay, identity verified by F
  L-->>D: full netmap, then deltas (peers, filter), keepalive 30s
```

- **State.** Networks, members, join-key hashes, ACLs and approved routes are part of the replicated cluster state (Raft). Liveness and endpoints are soft state in the leader's hub, so a device coming online never writes to the log. After a failover, devices reconnect to the new leader and re-report.
- **Any endpoint works.** Followers verify the device certificate and relay the request to the leader over master mutual TLS, carrying the verified identity in headers. The leader trusts those headers only on connections that present a master certificate. Netmap streams pass through unbuffered.
- **Netmap stream.** One HTTP/2 stream of JSON lines per device: a `full` message, then `delta` messages (upserted peers, removed peer IDs, the inbound filter when it changes), plus a keepalive every 30s. A device that is too slow to read is dropped and resyncs with a full map on reconnect, so the leader never buffers without bound.
- **Scale.** Measured with 10,000 streaming devices in 100 team networks on an M2 (`BenchmarkRouterHub`):
  - an endpoint change reaches every viewer in about 1 ms;
  - a full state reload (ACL recompiled, every device re-diffed) takes about 0.4 s.

  Per-device memory is proportional to the number of peers it sees.

## Security model

| Boundary | Control |
|---|---|
| Device → router | TLS 1.3. The router is verified against the cluster CA, whose hash is in the key (no trust on first use). Requests after join need a client certificate issued by that CA (OU `ziro-device`, 30 days, renewed with a CSR). |
| Device identity | The WireGuard, disco and TLS private keys are generated on the device and never leave it. The router binds a member to the hash of its TLS public key. Renewing with a new key revokes the old certificate at once. |
| Device certificates vs. masters | Device certificates carry OU `ziro-device` and only the client-auth EKU. Raft, the internal API and the data-key endpoint all require the master OU, and agents verify masters by name and server-auth EKU. |
| Join keys | 256-bit secrets. Only their SHA-256 is stored, compared in constant time. They expire (default 24h, at most 1 year) and are single-use unless `--reusable`. A device whose reply was lost can retry with its own TLS key. |
| Approval requests | By network ID only (16 random hex; names are guessable). At most 1000 pending per network, removed after 7 days. |
| Abuse | Per-IP rate limit (600/min) and per-device limit (60/min). 64 KiB bodies. Endpoints and versions are validated. Rejected credentials are audited at most once per IP per 10 minutes. |
| Revocation | `member rm`, network deletion or loss of authorization ends the device's stream within a quarter second and removes it from every peer's netmap. |
| Data plane | WireGuard end to end. Relays (R3) forward ciphertext between pairs the ACL allows. |
