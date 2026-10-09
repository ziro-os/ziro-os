# Tailscale

Reach a Ziro OS host (and let it reach your other devices) over a [Tailscale](https://tailscale.com) network, with no
public IP and nothing exposed to the internet. It is an opt-in module: nothing is installed until you enable it, so the
base image stays small.

```sh
ziroctl module enable tailscale        # downloads Tailscale, verified against the signed catalog
ziroctl tailscale up                   # prints a login link: open it, sign in, done
ziroctl tailscale allow ssh            # let tailnet devices reach this host's SSH
ziroctl tailscale status
```

For an unattended join (cloud-init, automation), give an auth key or an OAuth client secret from a file, stdin or a
hidden prompt:

```sh
ziroctl tailscale up --auth-key-file /root/ts.key --tag tag:server --hostname web1
echo "$KEY" | ziroctl tailscale up --auth-key-stdin
ziroctl tailscale up --login-server https://headscale.example.com
```

## Closed by default

A host joined to a tailnet is reachable by every device on it, so nothing is open until you say so.

| | Default | How to change it |
|---|---|---|
| Ports reachable from the tailnet | none | `ziroctl tailscale allow ssh` or `allow 5432/tcp` (the `tailscale0` interface only) |
| Tailscale SSH | off (sshd keeps port 22 and its hardening) | not offered |
| DNS (MagicDNS) | not accepted: the host's [smart DNS](dns.md) keeps `/etc/resolv.conf` | not offered yet |
| Routes other nodes advertise | not accepted | `ziroctl tailscale up --accept-routes` |
| Exit node, subnet router | off | not offered yet |
| Log upload to Tailscale | off | `ziroctl module enable tailscale --set telemetry=on` |

`tailscale allow` adds a firewall rule bound to the `tailscale0` interface (see `ziroctl firewall allow --iface`), so a
packet with a tailnet address that arrives on `eth0` does not match. The interface is never trusted wholesale, and your
tailnet's own access rules still apply on top. `ziroctl tailscale ls` shows what is open, `deny` closes it.

## How it is built

- **Unprivileged.** `tailscaled` runs as its own `tailscale` user with exactly `CAP_NET_ADMIN` and `CAP_NET_RAW`, every
  other capability dropped and `no_new_privs` set ([service capabilities](modules.md)), inside a cgroup (256 MiB, 256
  processes). Its state, including the node key, is a 0700 directory it owns, never part of a
  [backup](operations.md); its control socket is in a 0750 directory.
- **No key on a command line.** An auth key is read from a file, stdin or a hidden prompt and handed to Tailscale as a
  0600 file in a 0700 directory that is removed when the command ends. It is not stored, not in the environment, not
  logged. The node's own identity lives in the state directory.
- **Always the newest release, verified.** The binaries come from the signed module catalog: a daily job there takes the
  newest stable Tailscale, checks Tailscale's own signature, pins the sha256 and re-signs the catalog. The host checks the
  catalog signature and the sha256 (again at every boot). `ziroctl tailscale update` runs daily from cron, restarts
  Tailscale and, if the node does not come back connected within 30 seconds, puts the previous version back and raises an
  alert. `ziroctl tailscale update --check` shows what is available; `--set auto_update=false` turns the daily job off.
- **No port clash.** `tailscaled` listens on UDP 41642 (not its default 41641, which `zirocd` uses). `--set port=…`
  changes it, and `ziroctl tailscale up --open-port` opens it so peers can connect directly on a host with a public
  address; without it, connections still work through NAT traversal or Tailscale's relays. `ziroctl tailscale status`
  shows how many peers are direct and how many relayed.
- **No address clash.** Tailscale assigns addresses from `100.64.0.0/10`, the range the [router](router.md) mesh uses
  too. `ziroctl tailscale up` refuses when another interface already routes it (`--force` to join anyway).

## Commands

| Command | What it does |
|---|---|
| `ziroctl tailscale up` | Join a tailnet (login link, or an auth key from a file, stdin or a prompt) |
| `ziroctl tailscale status` | State, addresses, tailnet, direct and relayed peers, health warnings |
| `ziroctl tailscale ip` | This node's tailnet addresses |
| `ziroctl tailscale ping <peer>` | Whether and how a peer is reached |
| `ziroctl tailscale allow\|deny\|ls` | Ports open to the tailnet |
| `ziroctl tailscale down` | Disconnect and keep this node's identity |
| `ziroctl tailscale logout` | Leave and remove this node from the tailnet |
| `ziroctl tailscale update` | Upgrade from the signed catalog, with rollback |

`ziroctl doctor` reports the node (joined, peers online, Tailscale's own health warnings).

## Settings

`ziroctl module enable tailscale --set key=value`:

| Setting | Default | |
|---|---|---|
| `port` | `41642` | UDP port (1024-65535, not zirocd's, WireGuard's or the cluster mesh's) |
| `telemetry` | `off` | `on` lets tailscaled upload logs to Tailscale |
| `auto_update` | `true` | the daily `ziroctl tailscale update` |

Needs 512 MB of RAM (`--force` to override). Disabling the module (`ziroctl module disable tailscale`) stops tailscaled and
removes the binaries; `--purge` also removes the node's state. Run `ziroctl tailscale logout` first to remove the node from
your tailnet.

Design record: [RFC 0003](design/rfcs/0003-tailscale-module.md).
