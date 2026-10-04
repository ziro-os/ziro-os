# Ziro Router: global mesh networks

The router connects devices anywhere — laptops, CI runners, servers in other clouds, other Ziro clusters — into private networks, like a global network switch. Devices run **zirocd**, join with a key, get a stable address and name (`<device>.<network>.ziro`), and reach the peers the network's ACL allows over WireGuard.

| Piece | What it is | Status |
|---|---|---|
| Control plane | `ziroctl router`, served by `cluster-master` on every master (`/router/v1/*` on the cluster port, 7443) | shipped (R1) |
| Client | `zirocd` for Linux, macOS and Windows (amd64, arm64), signed releases with self-update | shipped (R2) |
| Relays + NAT traversal | `ziroctl router relay enable` (TLS relay + STUN), disco hole punching, `zirocd netcheck` | shipped (R3) |
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

## Client: zirocd

`zirocd` is a single static binary (about 8 MB) that runs as a system service and is controlled with the same binary:

| OS | Install | Tunnel | Split DNS |
|---|---|---|---|
| Linux (amd64, arm64) | `curl -fsSL https://raw.githubusercontent.com/ziro-os/ziro-os/main/scripts/install-zirocd.sh \| sh` | TUN `zr0`, systemd unit | `resolvectl` (systemd-resolved) |
| macOS (Intel, Apple silicon) | same script | `utunN`, launchd daemon | `/etc/resolver/<network>.ziro` |
| Windows (amd64, arm64) | `irm https://raw.githubusercontent.com/ziro-os/ziro-os/main/scripts/install-zirocd.ps1 \| iex` (elevated) | Wintun adapter `Ziro`, Windows service | NRPT rule |

```sh
sudo zirocd up --key zr1_...                     # or ZIROCD_KEY=zr1_... to keep it out of history
sudo zirocd up --key zr1_... --name build-01 --advertise-routes 10.0.0.0/16
zirocd status                                    # state, address, peers, handshakes, traffic
zirocd ping db-1
sudo zirocd down                                 # disconnect, keep the identity
sudo zirocd logout                               # disconnect and delete the keys
```

- **Data plane.** Userspace WireGuard (wireguard-go) with MTU 1280, over zirocd's own socket layer (below). Peers are configured one by one from netmap deltas, so a change never resets sessions it doesn't touch. On a 2-container Docker test on an M2 it carries about 2.7 Gbit/s. Linux hosts get a kernel fast path in R4.
- **Inbound filter.** The router's rules for this device are enforced on every packet. Replies to connections the device opened are let back in; anything else unsolicited is dropped (`zirocd status` counts drops).
- **Names.** `<device>.<network>.ziro` resolve through a tiny resolver on the device's own tunnel address. Only that domain is sent to it, so other DNS is untouched.
- **Keys and state.** The WireGuard, disco and TLS private keys are generated on the device. They live in `/var/lib/zirocd` (Linux), `/Library/Application Support/zirocd` (macOS) or `%ProgramData%\zirocd` (Windows, ACL'd to SYSTEM and Administrators). The join key is deleted once used. The CLI talks to the daemon over a root-only socket (an Administrators-only named pipe on Windows).
- **Endpoints.** A device reports its interface addresses plus the public address the relays see (STUN), and its home relay. See [Relays and NAT traversal](#relays-and-nat-traversal).

### Updates

zirocd follows the tools release stream (`tools/vX.Y.Z`), which is built for all six targets by `.github/workflows/tools-release.yml` with build-provenance attestations.

- Every 6 hours (with jitter) it checks for a newer version, or for the version the network admin pinned (`ziroctl router network set office --client-version X.Y.Z`).
- It installs only if `SHA256SUMS` carries the Ziro release signature (ed25519) and the binary matches. The swap is atomic, and the previous binary is kept.
- If the new binary fails to reach "connected" in two starts, it is rolled back automatically.
- `--auto-update notify` only reports in `zirocd status`; `off` disables checks. `sudo zirocd update` installs now.

## Relays and NAT traversal

Most devices sit behind NAT. zirocd finds a direct path when one exists, and uses a relay until then (or when none does), so traffic flows from the first packet.

```sh
# on a master with a public address (run it on several masters, in several regions)
ziroctl router relay enable sg-1 --public relay-sg.example.com:8443
ziroctl router relay ls
zirocd netcheck            # on a device: UDP, NAT type, public address, relay latency
```

| Mechanism | How |
|---|---|
| One socket | WireGuard, path discovery (disco) and STUN share the device's WireGuard UDP port, so the NAT mapping a relay observes is the one peers can use |
| Public address | Every 20s, STUN to each relay; the lowest-latency relay becomes the device's **home relay**. Both go to the router, which pushes them to peers |
| Hole punching | Disco pings (NaCl box between the two devices' disco keys) go to every candidate address of the peer at once. A ping relayed through the home relay asks the peer to ping back now, so both NATs open together. The first pong picks the path; a faster one replaces it |
| Path choice | Per packet: the direct address while its last pong is under 7s old (pings repeat every 2s on active peers), otherwise the peer's home relay. Path changes never interrupt the WireGuard session |
| Relays | TLS 1.3 over TCP (works where UDP is blocked). The relay identifies each device by its certificate, forwards only within one network, rate-limits each device (`--rate-mbps`, default 200), and drops a device within a second of its removal. It only ever sees WireGuard ciphertext |

`zirocd status` shows each peer's path, `direct 203.0.113.9:41641 (12ms)` or `relay sg-1`.

**What punches through:** home routers, cloud NAT gateways and most carrier NATs, which map endpoint-independently. Under "symmetric" NAT, where the mapping varies by destination (`zirocd netcheck` reports it), a direct path forms only if the peer is reachable; otherwise traffic stays on the relay.

Measured in `tests/router/e2e.sh` (two devices, each behind its own firewalled NAT, in Docker on an M2):
- hole punching gives a direct path at about 2.6 Gbit/s;
- blocking UDP between the NATs moves traffic to the relay within seconds (at the 200 Mbit/s per-device limit);
- unblocking returns to the direct path.

The relay transport is TLS/TCP only, DERP-style. QUIC datagrams would serve relayed bulk traffic better; they are deferred because relays are the fallback path.

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
| Data plane | WireGuard end to end. Relays forward ciphertext only, only within one network, and identify senders by certificate, never by what a frame claims. A device's own ACL filter still decides what it accepts. |
| Path discovery | Disco messages are NaCl-boxed between disco keys the router distributed: a forged or replayed ping from anyone else is dropped, and a relayed one must come from the key it claims. Ping rounds are rate-limited, so two peers cannot amplify each other |
