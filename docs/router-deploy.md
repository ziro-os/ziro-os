# Running the Ziro router in production

This guide takes you from nothing to a multi-region router: three planets, a moon in each region where you have devices, and devices that join with a key. Read [router.md](router.md) first for what each part does. Here we only cover how to deploy and run it.

## The shape of it

```mermaid
flowchart LR
  subgraph Planets["Planets (cluster masters, Raft)"]
    P1[planet eu] --- P2[planet us] --- P3[planet ap]
  end
  M1[moon fra] -. relay map .-> P1
  M2[moon sgp] -. relay map .-> P3
  L1[laptop] -- netmap --> P1
  L2[server] -- netmap --> P3
  L1 <== WireGuard, direct when possible ==> L2
  L1 -. relayed when not .- M1 -. .- L2
```

| Role | What it is | Needs |
|---|---|---|
| Planet | A Ziro OS master. It holds the router state in Raft and streams netmaps to devices near it | A public address on tcp/7443 |
| Moon | `zirocd moon` on any Linux host or container. It relays traffic between devices that can't reach each other directly | A public address on tcp/8443 and udp/3478 |
| Leaf | A device running `zirocd` (Linux, macOS, Windows) or a Ziro OS host | Outbound internet only |

Planets never carry device traffic. Devices talk to each other directly, and fall back to the nearest relay only when no direct path exists.

### Ports

| From | To | Port | Why |
|---|---|---|---|
| devices, moons | planets | tcp/7443 | Registration, netmaps, relay map |
| planets | planets | tcp/7443, tcp/7444 | Cluster API and Raft (keep 7444 private if you can) |
| devices | moons | tcp/8443, udp/3478 | Relay (TLS and UDP) and STUN |
| devices | devices | udp/41641 | WireGuard, direct paths (nothing needs to be opened: hole punching handles NAT) |

### Sizing

These numbers are measured, in Docker on an Apple M2, by `BenchmarkRouterHub`, `TestRelayMemoryPerDevice` and `tests/router/e2e.sh`.

- **Planet:** about 4 KB of memory per connected device. An endpoint change reaches 10,000 devices in about 1 ms. Two vCPUs and 2 GB of RAM are plenty for tens of thousands of devices. Run 3 planets (5 if you need to survive two failures).
- **Moon:** about 15 KB per connected device, and 0.8–1.3 Gbit/s of relayed traffic. One vCPU and 512 MB carries a region comfortably. Add moons for more relay capacity: devices spread across the relays nearest to them.
- **Device:** zirocd idles at about 16 MiB and stays under 256 MiB at full speed (see [Memory](router.md#client-zirocd)).

## 1. Planets

Install Ziro OS on three hosts, ideally in three regions or availability zones ([installation guide](installation-guide.md)). Then:

```sh
# on the first planet
ziroctl cluster init --advertise 203.0.113.10
ziroctl cluster token
# on the other two
ZIRO_CLUSTER_TOKEN=<token> ziroctl cluster join 203.0.113.10:7443 --ca-hash sha256:<hash> --control-plane
# on any planet
ziroctl cluster members
```

`cluster members` should list three voters and one leader. Every planet serves devices; the leader only matters for writes.

## 2. Public endpoints

Give each planet its own DNS name and list them all:

```sh
ziroctl router endpoints set eu.router.example.com:7443 us.router.example.com:7443 ap.router.example.com:7443
```

Don't put the planets behind a single load balancer name. Devices time a TLS handshake to each planet and use the nearest one; a single name hides the distances and sends everyone to whatever the balancer picks. Keys carry this list. Devices also learn about planets added later from their netmap.

## 3. Router configuration as code

Keep the router's configuration in git and apply it on any planet. Apply shows what it will change, changes only that, and does nothing when the file already matches. It adds and edits networks and moons but never deletes them (use `ziroctl router network rm` or `ziroctl router moon rm` for that).

```yaml
# router.yaml
host:
  version: 1
  router:
    endpoints: [eu.router.example.com:7443, us.router.example.com:7443, ap.router.example.com:7443]
    sso:
      issuer: https://login.example.com
      client_id: ziro-router
      client_secret_file: /root/oidc.secret     # read at apply time, stored sealed with the cluster secrets
    networks:
      - name: office
        client_version: 1.0.30                   # pin the fleet's zirocd version ("latest" unpins)
        sso: {domains: [example.com], tags: [laptop], key_expiry_hours: 2160}
        acl:
          groups:
            admins: [alice-laptop, bob-laptop]
          rules:
            - {src: ["group:admins"], dst: ["*:*"]}
            - {src: ["tag:laptop"], dst: ["tag:web:443"], proto: tcp}
            - {src: ["tag:web"], dst: ["tag:db:5432"], proto: tcp}
    moons:
      - {name: fra-1, public: fra.relay.example.com:8443}
      - {name: sgp-1, public: sgp.relay.example.com:8443}
```

```sh
ziroctl apply -f router.yaml --dry-run
ziroctl apply -f router.yaml
```

New networks deny everything until a rule allows it. For each new moon, apply prints a registration token on stderr. It is shown once and is valid for an hour; `ziroctl router moon token fra-1` issues a fresh one.

## 4. Moons

A moon needs a public address and nothing else. It keeps its key and certificate in one directory and renews the certificate itself. Pick whichever way of running it suits the host.

**Docker:**

```sh
docker run -d --name moon --read-only --restart unless-stopped \
  -p 8443:8443/tcp -p 3478:3478/udp -v zirocd-moon:/var/lib/zirocd-moon \
  -e ZIROCD_MOON_TOKEN=zm1_... ghcr.io/ziro-os/zirocd
```

The token is only needed on the first start. After that the volume holds the moon's identity; recreate the container without the variable.

**Any Linux host with systemd.** Download the binary and check it:

```sh
v=1.0.30
curl -fsSLO https://github.com/ziro-os/ziro-os/releases/download/tools/v$v/zirocd-linux-amd64
curl -fsSLO https://github.com/ziro-os/ziro-os/releases/download/tools/v$v/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
gh attestation verify zirocd-linux-amd64 --repo ziro-os/ziro-os    # optional: build provenance
install -m 0755 zirocd-linux-amd64 /usr/local/bin/zirocd
```

Register it once, then install a service:

```sh
ZIROCD_MOON_TOKEN=zm1_... zirocd moon --dir /var/lib/zirocd-moon --register-only
```

```ini
# /etc/systemd/system/zirocd-moon.service
[Unit]
Description=Ziro moon (router relay)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/zirocd moon --dir /var/lib/zirocd-moon --metrics-listen 127.0.0.1:9102
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/zirocd-moon
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
```

```sh
systemctl enable --now zirocd-moon
```

**Ziro OS host:**

```sh
ziroctl router moon join --token-file /root/fra-1.token
```

**Kubernetes:** run it as a DaemonSet on a few nodes with public addresses. Use `hostNetwork: true`, so the moon sees devices' real source addresses (STUN needs them) and relayed packets skip the extra NAT. Put the token in a Secret mapped to `ZIROCD_MOON_TOKEN`, keep `/var/lib/zirocd-moon` on a hostPath, and set `readOnlyRootFilesystem: true` and `runAsNonRoot: true`. The image already runs as uid 65532.

Check it from a planet:

```sh
ziroctl router moon ls
```

The status shows `registered`, and `ON THIS PLANET` is `true` on the planet the moon streams from. Devices start using the moon within seconds of it registering.

A planet can relay too (`ziroctl router relay enable eu-1 --public eu.router.example.com:8444 --listen :8444`). Give it a port other than 8443, which is the admin API's.

## 5. Devices

```sh
# on a planet: a key for laptops, or let people sign in (network invite)
ziroctl router key create office --reusable --expiry 720h --tags laptop
ziroctl router network invite office

# on a laptop or server
sudo zirocd up --key zr1_...
sudo zirocd up --sso --key zr1_...           # sign in with your company account

# on a Ziro OS host
ziroctl router join --key-file /root/office.key

# CI runners and autoscaling groups: removed 10 minutes after going offline
ziroctl router key create office --reusable --ephemeral --tags ci
```

Pass keys through `ZIROCD_KEY` or a key file rather than the command line, where other users of the host can read them in the process list.

## 6. Monitoring

Planets expose Prometheus metrics on the admin API; a viewer token is enough:

```sh
ziroctl api token create prometheus --role viewer
```

```yaml
scrape_configs:
  - job_name: ziro-planets
    scheme: https
    tls_config: {ca_file: /etc/prometheus/ziro-api.pem}   # the planet's API certificate
    authorization: {credentials_file: /etc/prometheus/ziro-viewer.token}
    metrics_path: /api/v1/metrics
    static_configs: [{targets: ['eu.router.example.com:8443', 'us.router.example.com:8443', 'ap.router.example.com:8443']}]
  - job_name: ziro-moons            # --metrics-listen; scrape over a private network
    static_configs: [{targets: ['10.1.0.5:9102', '10.2.0.5:9102']}]
```

The alerts worth having:

| Alert | Expression | Means |
|---|---|---|
| Planet cut off | `ziro_router_planet_up == 0` for 5m | That planet no longer gets the other planets' device state |
| Raft without a leader | `max(ziro_cluster_raft_leader) == 0` for 1m | Writes (joins, renewals, config) are failing; netmaps still flow |
| Moon blind | `ziro_moon_relaymap_up == 0` for 3m | The moon can't reach any planet; it stops relaying after 5 minutes |
| Moon certificate | `ziro_moon_cert_expiry_seconds < 86400` | Renewal is failing (it renews 3 days before expiry) |
| Relay drops | `rate(ziro_moon_dropped_total[5m]) > 100` | Devices hit the rate limits, or something sends from spoofed addresses |

## 7. Backup and restore

The router state is part of the cluster state. Back up any planet, and keep the archive off the host:

```sh
ziroctl backup create --remote ziro_s3:ziro-backups
ziroctl backup restore ziro_s3:ziro-backups/ziro-backup-20261004-020000.tar.gz
```

Moons hold nothing worth backing up. A rebuilt moon registers again with `ziroctl router moon token <name>`.

## 8. Upgrades

1. **Planets**, one at a time: `ziroctl update` on each. Wait until `ziroctl cluster members` shows it back as a voter before the next. Devices on the restarting planet move to another planet within seconds.
2. **Moons**: pull the new image or binary and restart them one at a time. Devices fail over to their second relay meanwhile.
3. **Devices** update themselves from the signed release stream. Pin a version per network (`client_version` in the file, or `ziroctl router network set office --client-version X.Y.Z`) to roll out in stages.

## 9. When something fails

| Failure | What happens | What to do |
|---|---|---|
| A planet goes down | Its devices reconnect to the next nearest planet within seconds. Direct paths don't notice | Bring it back, or `ziroctl cluster member rm <id>` and join a new one |
| The leader goes down | Raft elects another in seconds. No device reconnects | Nothing |
| A majority of planets down | Netmaps and existing connections keep working from the survivors; joins, renewals and config changes wait | Restore the planets (or restore a backup on a new cluster) |
| A moon goes down | Devices relaying through it move to their other relay in seconds | Restart or replace it |
| A moon loses every planet | It keeps relaying for 5 minutes, then stops (it can't learn revocations) | Fix its outbound path to the planets |
| A region is cut off | Devices there keep direct paths; relayed traffic moves to the next nearest moon | Nothing, or add a second moon in that region |

## Security checklist

- [ ] Planets are reachable from the internet only on tcp/7443; Raft (7444) and the admin API (8443) are on private networks or firewalled to known addresses.
- [ ] Every network has an ACL that allows only what's needed (they start denying everything).
- [ ] Sign-in policies name domains or groups, and signed-in devices expire (`key_expiry_hours`).
- [ ] Join keys expire. Reusable keys are scoped with tags, and ephemeral keys are used for CI.
- [ ] Moon tokens, join keys and the SSO client secret never go into git. The router file refers to the secret by path, and tokens are printed once.
- [ ] Removed people and devices are removed from the router (`ziroctl router member rm`); this ends their sessions within a second.
- [ ] Backups of a planet are encrypted at rest and kept off the host: they hold the cluster CA key (`--include-secrets` adds app secrets).
- [ ] Moons run as non-root with a read-only root (the image does by default), and their metrics port isn't public.
- [ ] `ziroctl audit log` is shipped to your log system; every router change and sign-in is in it.
