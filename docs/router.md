# Ziro Router: global mesh networks

The router connects devices anywhere — laptops, CI runners, servers in other clouds, other Ziro clusters — into private networks, like a global network switch. Devices run **zirocd**, join with a key, get a stable address and name (`<device>.<network>.ziro`), and reach the peers the network's ACL allows over WireGuard.

| Piece | What it is | Status |
|---|---|---|
| Control plane | `ziroctl router`, served by `cluster-master` on every master (`/router/v1/*` on the cluster port, 7443). Every master ("planet") serves netmaps; devices use the nearest one | shipped (R1; every planet serves since G1) |
| Client | `zirocd` for Linux, macOS and Windows (amd64, arm64), signed releases with self-update | shipped (R2) |
| Relays + NAT traversal | `ziroctl router relay enable` (TLS relay + STUN), disco hole punching, `zirocd netcheck` | shipped (R3) |
| Ziro OS hosts, subnet routers | `ziroctl router join` (zirocd ships in the full image), routed LANs and cluster meshes | shipped (R4) |
| SSO | OIDC device-code sign-in (`zirocd up --sso`), expiring device keys, `user:` ACL selectors | shipped (R5) |

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
- **Sign-in:** users join with their company account (`zirocd up --sso`). See [Single sign-on](#single-sign-on).

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

- **Data plane.** Userspace WireGuard (wireguard-go: batched UDP with GSO/GRO, TUN offload) with MTU 1280, over zirocd's own socket layer (below).
  - On the same host, this path measured faster than kernel WireGuard: 2.4–2.6 Gbit/s through two NATs with the ACL filter on, against 1.7–1.8 Gbit/s for a plain kernel tunnel in Docker on an M2. CI runners reach 6.6 Gbit/s.
  - A kernel mode would also lose hole punching and relay fallback, so there isn't one.
  - The ACL filter costs about 47 ns per packet with no allocations (`BenchmarkFilterWrite`). Peers are configured one by one from netmap deltas, so a change never resets sessions it doesn't touch.
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

## Single sign-on

People sign their devices in with your identity provider, through any OIDC provider with the OAuth 2.0 device authorization grant (RFC 8628): Google, Microsoft Entra ID, Okta, Keycloak, Authentik, Dex and others.

```sh
# once, on a master: register an OAuth client with the device-code grant at the provider
ziroctl router sso set --issuer https://login.example.com --client-id ziro-router [--client-secret-file f]
# per network: who may sign in, which tags their devices get, how long they stay in
ziroctl router network set office --sso-domains example.com --sso-tags laptop \
    --sso-group-tags admins=admin --key-expiry 2160h
ziroctl router network invite office      # the zr1_ invite users sign in with
```

On a device:

```
$ sudo zirocd up --sso --key zr1_...
To sign in, open https://login.example.com/device
and enter the code:  WDJB-MJHT
✓ connected: alice-laptop.office.ziro  100.64.0.7
  signed in until 2027-04-02 (zirocd up --sso to renew)
```

**How it works.** The router runs the flow, so zirocd never talks to the identity provider and the client secret never leaves the masters (it's stored and sealed with the cluster secrets).
1. The leader asks the provider for a device code and hands the URL and user code to zirocd.
2. The leader polls the provider until the user approves.
3. It verifies the ID token: issuer, audience (your client ID), signature against the provider's published keys, and expiry.
4. It applies the network's policy, and the device's next poll receives its certificate.

| Policy | Rule |
|---|---|
| Who | The email must be verified by the provider (`--trust-unverified-email` for providers that never say), and in `--sso-domains` and/or a member of `--sso-groups` (claim `groups`, or `--groups-claim`). A network allows sign-in only with at least one of these: "any account of the provider" is never an option |
| Tags | `--sso-tags` for every signed-in device, plus `--sso-group-tags group=tag1+tag2` per group. Use them in ACLs, alongside `user:<email>` |
| Expiry | Signed-in devices expire after `--key-expiry` (default 180 days, i.e. 4320h). An expired device is dropped from every netmap and relay within a minute; `zirocd status` warns two weeks ahead, and `zirocd up --sso` renews. Servers: `ziroctl router member expiry office db-1 --never` |
| Audit | Every sign-in, refusal and failed verification is in the audit log, with the user's email |

As with every device-code flow, a user should only enter a code that their own `zirocd up --sso` printed.

## Ziro OS hosts

The full Ziro OS image ships zirocd. `ziroctl router` runs it as the `zirocd` ziro-init service:

```sh
ziroctl router join --key-file /root/office.key        # or ZIROCD_KEY=zr1_... ziroctl router join
ziroctl router join --key-file k --name gw-1 --advertise-routes 10.200.0.0/16
ziroctl router status
ziroctl router leave                                    # logout + stop the service
```

- `join` allows WireGuard (udp/41641) and trusts `zr0` in the host firewall. That's safe because zirocd's filter has already applied the network's ACL to every packet that reaches `zr0`.
- The key never appears in argv: it travels through the environment, and the audit log redacts any `zr1_` string or `--key` value.
- `<device>.<network>.ziro` names go through Ziro DNS as a forward rule (`ziroctl dns forward`), added and removed by zirocd.
- **Updates:** on Ziro OS, `ziroctl update` installs zirocd with the other tools and records its hash in the integrity baselines (FIM and IMA). zirocd's own self-update stands down there, so the baselines always know its binary. Elsewhere zirocd updates itself.

## Subnet routers

A Linux device can carry a whole subnet into the network: a LAN, a VPC, or a Ziro cluster's mesh and pod networks. Devices that aren't running zirocd are reachable through it.

```sh
# on the router device (Linux; Ziro OS: ziroctl router join ... --advertise-routes)
sudo zirocd up --advertise-routes 10.200.0.0/16,10.201.0.0/16     # re-advertises without re-joining
# on a master
ziroctl router route approve office gw-1 10.200.0.0/16
ziroctl router route approve office gw-1 10.201.0.0/16
```

Write the ACL rules with the subnet as the destination, for example `dst: ["10.200.0.0/16:443"]`.

- **On approval:**
  - Every device the ACL allows routes the subnet into its tunnel.
  - The router device turns on IP forwarding and masquerades the network's traffic out of its LAN interfaces (nft table `inet zirocd`, or iptables), so LAN hosts need no route back.
- **On revocation, or when the route is withdrawn:** the NAT rules are removed.

**Bridging two Ziro clusters:**
1. Join a gateway node of each cluster.
2. Advertise each cluster's mesh (`10.200.0.0/16` by default) and pod network (`10.201.0.0/16`). Give the clusters different CIDRs if both use the defaults.
3. Approve both sides.
4. Allow them in the ACL.

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
| Public address | Every 20s, STUN to each relay. The device registers with its **two nearest relays** and reports them, with their round trips, to the router, which pushes them to peers |
| Hole punching | Disco pings (NaCl box between the two devices' disco keys) go to every candidate address of the peer at once. A ping relayed through the home relay asks the peer to ping back now, so both NATs open together. The first pong picks the path; a faster one replaces it |
| More direct paths | **Port mapping:** zirocd asks the home or office router to forward its WireGuard port, through PCP, NAT-PMP or UPnP IGD, as ZeroTier does. It asks only the default gateway on a private address, for UDP only, with a 2h lease renewed at half-life and removed on exit. **Hard NATs:** when a device's NAT gives each destination its own port (two relays see different ports), a peer behind an easy NAT probes ±32 ports around the ones the relays saw, budgeted to one round per 15s. **IPv6:** relays are probed over both IPv4 and IPv6, and direct paths rank same-LAN, then IPv6, then IPv4, with a 20% round-trip allowance before a lower rank wins |
| Roaming | A 2s watch on the host's addresses and default gateway. On a change (Wi-Fi to LTE, a new DHCP lease), zirocd forgets the old paths, re-learns its public address, re-binds relay sessions, reconnects to the router at once, and pings every active peer |
| Path choice | Per packet: the direct address while its last pong is under 7s old (active peers are pinged every second; 3 missed pongs drop a path in about 3s), otherwise a relay. WireGuard never "roams" a peer by itself: the socket layer owns every path. The relay is chosen per peer: of the relays the peer is registered with, the one with the lowest round trip *for the pair* (ours + the peer's), with instant failover to the other. Path changes never interrupt the WireGuard session |
| Relays | **UDP first, TLS as the fallback.** Each relay connection is TLS 1.3, where the relay checks the device's certificate. Over it, the relay hands out a UDP session (ID + key). The device then binds the session to its WireGuard socket's address with an HMAC-authenticated, timestamped hello, so a replay can't move it. After that, relayed packets are plain UDP datagrams on the same port as STUN, forwarded with batched GRO/GSO I/O and no allocation per packet. Where UDP to the relay is blocked, or a hello goes unanswered for 3s, traffic moves to the TLS connection within seconds, and back once UDP answers again. The relay forwards only within one network, takes the sender's identity from its session (never from the packet), rate-limits each device (`--rate-mbps`, default 1000) and the relay as a whole (`--max-mbps`, default 10000), and drops a device within a second of its removal. It only ever sees WireGuard ciphertext |

`zirocd status` shows each peer's path: `direct 203.0.113.9:41641 (12ms)`, `relay sg-1 udp`, or `relay sg-1 tls`.

**What goes direct:**
- **Endpoint-independent NATs** (home routers, cloud NAT gateways, most carrier NATs): by hole punching.
- **Routers that offer PCP, NAT-PMP or UPnP:** through a port mapping.
- **A hard NAT facing an easy one:** by port probing.
- **Two hard NATs without port mapping:** the relay (UDP, or TLS where UDP is blocked) carries the traffic, by design.

Measured in `tests/router/e2e.sh` (two devices, each behind its own firewalled NAT, in Docker on an M2):

| Path | Throughput |
|---|---|
| Direct (hole punched; also through a hard NAT by port probing, and after roaming to another NAT) | 2.0–3.2 Gbit/s |
| UDP relay (UDP between the NATs blocked) | 0.9–1.4 Gbit/s |
| TLS relay (UDP to the relay blocked too) | 0.6–0.7 Gbit/s |

Each step down happens within seconds, and each recovers on its own when the blocked path returns. The same test checks:
- roaming: direct again within 20s;
- a hard NAT: a direct path on a port found by probing;
- port mapping against a real `miniupnpd` (PCP).

`zirocd netcheck` reports the NAT type (easy, hard or unknown), the port-mapping protocol and mapped address, IPv6 reachability, and each relay's latency and transport. Path-discovery debugging: run the daemon with `ZIROCD_DEBUG=disco`.

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

Selectors are `*`, `tag:<t>`, `group:<g>`, `member:<name>`, `user:<email>` (devices signed in by that user) or a CIDR. Destinations add ports: `*`, `443`, `8000-8100` or `22,443`. Unknown keys in the file are an error, so a typo can't silently drop a rule.

- `ziroctl router acl test office web-1 db-1 5432/tcp` answers from the same code the devices enforce.
- **Least visibility:** a device's netmap holds only the peers it may talk to (in either direction). Every other member's existence, keys and addresses stay hidden from it.
- Rules are enforced by the **receiving** device. WireGuard's cryptokey routing already guarantees that a packet's source address belongs to the peer that sent it.

**Subnet routes.** See [Subnet routers](#subnet-routers).

**Client version.** `ziroctl router network set office --client-version 1.0.21` pins the fleet's zirocd version (`latest` unpins it). Devices update to it through the signed release stream.

## How it works

```mermaid
sequenceDiagram
  participant D as zirocd
  participant P as nearest planet
  participant L as leader
  participant Q as other planets
  D->>P: TLS 1.3, verify cluster CA (pin from key)
  D->>P: POST /register {join key, WG + disco keys, CSR}
  P->>L: relay over master mTLS (writes only)
  L->>L: Raft commit member; sign device cert (30 days)
  L-->>D: cert, addresses
  D->>P: POST /map (device cert, session epoch)
  P-->>D: full netmap from P's own replica, then deltas, keepalive 30s
  P->>Q: this device's endpoints and liveness (planet mesh)
```

- **Planets.** Every master runs the netmap hub from its own Raft replica. Devices stream from the nearest one: zirocd times a TLS handshake to each planet at start, every 10 minutes and after a network change, and moves only when another planet is a quarter faster. Only writes (`register`, `renew`) go to the leader. A leader change moves no stream.
- **State.** Networks, members, join-key hashes, ACLs and approved routes are part of the replicated cluster state (Raft). Liveness and endpoints are soft state: each planet keeps it for the devices streaming from it and streams it to every other planet over master mutual TLS. When a device moves to another planet it starts a newer session (an epoch from its own clock), and the newest session wins everywhere. Soft state never admits a device; membership comes only from Raft.
- **Replica lag.** A device that registered a moment ago may reach a planet whose replica hasn't applied that write yet. That planet relays the request to the leader instead of answering "unauthorized", which zirocd would take for a revocation.
- **Netmap stream.** One HTTP/2 stream of JSON lines per device: a `full` message, then `delta` messages (upserted peers, removed peer IDs, the inbound filter when it changes, the planet list when it changes), plus a keepalive every 30s. Each peer is encoded once per change and the same bytes go to every device that sees it. A device that is too slow to read is dropped and resyncs with a full map on reconnect, so a planet never buffers without bound.
- **Scale.** Measured with 10,000 streaming devices in 100 team networks on an M2 (`BenchmarkRouterHub`):
  - an endpoint change reaches every viewer on a planet in about 1 ms;
  - a full state reload (ACL recompiled, every device re-diffed) takes about 0.4 s.

  Per-device memory is proportional to the number of peers it sees.
- **Metrics.** `/api/v1/metrics` on each master adds `ziro_router_streams` (devices on this planet), `ziro_router_devices{state}` and `ziro_router_planet_up{planet}`.

## Security model

| Boundary | Control |
|---|---|
| Device → router | TLS 1.3. The router is verified against the cluster CA, whose hash is in the key (no trust on first use). Requests after join need a client certificate issued by that CA (OU `ziro-device`, 30 days, renewed with a CSR). |
| Sign-in | The router verifies ID tokens itself (issuer, audience, JWKS signature, expiry) and requires a verified email and a domain or group policy; the client secret stays sealed on the masters; signed-in devices expire and are re-authorized by signing in again |
| Device identity | The WireGuard, disco and TLS private keys are generated on the device and never leave it. The router binds a member to the hash of its TLS public key. Renewing with a new key revokes the old certificate at once. |
| Device certificates vs. masters | Device certificates carry OU `ziro-device` and only the client-auth EKU. Raft, the internal API and the data-key endpoint all require the master OU, and agents verify masters by name and server-auth EKU. |
| Join keys | 256-bit secrets. Only their SHA-256 is stored, compared in constant time. They expire (default 24h, at most 1 year) and are single-use unless `--reusable`. A device whose reply was lost can retry with its own TLS key. |
| Approval requests | By network ID only (16 random hex; names are guessable). At most 1000 pending per network, removed after 7 days. |
| Abuse | Per-IP rate limit (600/min) and per-device limit (60/min). 64 KiB bodies. Endpoints and versions are validated. Rejected credentials are audited at most once per IP per 10 minutes. |
| Revocation | `member rm`, network deletion or loss of authorization ends the device's stream within a quarter second of the planet applying the change, and removes it from every peer's netmap. |
| Planet mesh | Planets exchange soft state only over master mutual TLS. Entries for devices that aren't authorized members are dropped, and endpoint and relay lists are capped, so a planet can't be flooded and soft state can't grant access. |
| Data plane | WireGuard end to end. Relays forward ciphertext only, only within one network, and identify senders by certificate, never by what a frame claims. A device's own ACL filter still decides what it accepts. |
| Underlay vs overlay | An address inside a prefix routed through the tunnel (the network, approved subnet routes) is never used as a WireGuard path, so packets can't loop into the tunnel |
| Path discovery | Disco messages are NaCl-boxed between disco keys the router distributed: a forged or replayed ping from anyone else is dropped, and a relayed one must come from the key it claims. Ping rounds are rate-limited, so two peers cannot amplify each other |
