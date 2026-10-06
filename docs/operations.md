# Operating a host

Day-to-day commands for keeping a Ziro OS host healthy: what it shows at login, what uses it,
reclaiming disk, how it protects itself from running out of memory, and keeping `ziroctl` current.

## Login summary

Every login (and the boot console) shows a short summary, from `ziroctl motd`:

```
  ▀▀█ █ █▀█ █▀█  █▀█ █▀▀   1.0.17
  █▄▄ █ █▀▄ █▄█  █▄█ ▄▄█   web-1 · Proxmox VE / QEMU KVM · x86_64 · 6.18.54-ziro · up 3d 4h

  CPU       2 vCPU  load 0.42 0.38 0.31
  Memory    █████████░░░░░  2.5 GiB / 3.9 GiB     64%
  Disk /    ██████░░░░░░░░  8.1 GiB / 19.0 GiB    41%
  Network   172.26.1.108 eth0 · mesh 10.200.0.1 · pods 10.201.0.1
  Workload  5 containers · cluster master 3/3 nodes ready · api off

  ! clamd killed 2x for memory    ziroctl service status clamd
  ! ziroctl 1.0.18 available      ziroctl update
```

- **Terminals:** colors and glyphs follow the terminal. You get brand colors in 24-bit (`COLORTERM=truecolor`),
  256 or 16 colors, and plain ASCII on serial consoles (`TERM=vt100`/`vt220`/`dumb`) and non-UTF-8 locales.
  `NO_COLOR` turns colors off.
- **Live media** shows a `LIVE` tag and points at `ziroctl install`. Installed hosts show no mode label.
- **Cost:** it starts no processes. The container count comes from the cgroups.
- **Network** lists each address once. The default-route interface comes first, then other NICs, the cluster mesh
  (`mesh`) and the pod gateway (`pods`). Container interfaces aren't shown.
- **Attention** (`!` lines) appears only when something needs you, each with the command that deals with it. It
  flags:
  - memory pressure, or memory almost exhausted
  - a disk 85% or more full
  - a service killed for exceeding its memory limit
  - an enabled service that isn't running
  - the firewall disabled
  - cluster nodes not ready
  - an available `ziroctl` update
- `ziroctl motd --json` gives the same data for scripts.

## What uses the host: `system top`

```sh
ziroctl system top                   # interactive
ziroctl system top --once            # one snapshot
ziroctl system top --json            # for scripts; also GET /api/v1/system/top
```

There are three panes:
- **Containers** (`c`): CPU, memory against its limit, network and block I/O rates, and PIDs. It's read straight
  from each container's cgroup, like `docker stats`.
- **Processes** (`p`): PID, user, CPU, RSS, state, and the service or container each one belongs to.
- **Network** (`n`, or `--pane network`):
  - Interface rates (bytes and packets, errors, drops), with a 60-sample rx/tx graph for the primary interface.
  - Every connection the kernel tracks, with its direction (`in` when the remote end opened it), state and
    traffic per second. The source is conntrack, so container traffic behind NAT is included.
    `net.netfilter.nf_conntrack_acct` (set at boot) supplies the byte counters.
  - The busiest remote peers, and the listening ports with the process behind each.
  - Without conntrack it lists sockets and their states, with no byte counts.

Keys:
- `tab`, `c`, `p` and `n` switch panes.
- `s` cycles the sort: CPU, memory or name; in the network pane, rate, total or remote.
- `/` filters (a name, an IP or a port).
- `k` stops the top row of the containers or processes pane, after asking.
- `q` quits.

It reads `/proc` and cgroup files directly, and only for the pane on screen. One read buffer is reused, and the
heap is capped at 24 MiB, so it stays light on a busy host.

## Disk: `system df` and `system prune`

```sh
ziroctl system df                        # usage by category, and what a prune can reclaim
ziroctl system prune --dry-run           # show the plan
ziroctl system prune                     # show the plan, ask, remove
ziroctl system prune -y --only images,logs
ziroctl system prune --all               # also drop the upgrade rollback generation
```

Prune removes only what nothing uses:
- stopped containers that no app or cluster owns
- images no container uses. A container counts as using an image by its full name (`mysql:8.4` and
  `docker.io/library/mysql:8.4` are the same image) or by digest. An image that a container starts using between
  the plan and the removal is kept.
- rotated logs
- temp files in `/tmp` and `/var/tmp` older than 7 days that no process has open
- the package cache
- the upgrade rollback generation, with `--all` only (after that, the last upgrade can't be rolled back)

App data, volumes, secrets and `/etc` are never touched.

Logs over 10 MB are rotated hourly, keeping 3 gzip-compressed generations (`<log>.1.gz` is the newest).

When `/var` reaches 90%, the sentinel prunes images, rotated logs, stale temp files and caches on its own, and
sends a `disk` alert saying what it freed. The threshold is `disk_prune_percent` in `/etc/ziro/sentinel.json`; `0`
turns this off.

## Services that stay up: `doctor`

Every long-running service (sentinel, crond, cluster-agent, cluster-master, ziro-api, gateway, plugin daemons) is
supervised by ziro-init:
- **Restart:** a daemon that exits is restarted with a crash-loop backoff of 1 s doubling to 60 s, with no limit.
- **Ownership:** daemons are always children of PID 1, whoever started them, so no exit goes unseen.
- **Second line:** once a minute, the sentinel starts any enabled service that is down, for example one stopped
  by hand, and sends a `service` alert.

```sh
ziroctl doctor          # kernel, storage, containerd, network, every enabled service, cluster link, disk, firewall
ziroctl doctor --fix    # start services that are down, restart the cluster agent, prune logs and temp files; run a cluster heal pass; check again
ziroctl doctor --json
```

On a cluster master, `doctor` shows `Cluster nodes ready` and one row per unhealthy node (NotReady time, conditions,
a cordon set by auto-healing; see [auto-healing](clustering.md#auto-healing)). Every cluster node also shows
`Cluster heartbeat`, from the agent's own record of its last heartbeat to the master.

Rows are `ok`, `warn` or `fail`, plus `fixed` after `--fix`. A failing row shows what `--fix` does, or the command
to run. The exit status is non-zero only when a critical check fails (`ziroctl upgrade` gates on those).

## Memory: how a host protects itself

A small host running a large plugin next to databases is the classic way to run out of memory. Ziro OS
handles it in layers.

1. **Service cgroups.** Every service runs in its own cgroup.
   - **Platform daemons** (sshd, containerd, the ziroctl services) live in `/sys/fs/cgroup/ziro/system`. That cgroup
     keeps a memory reservation (5% of RAM, at most 256 MiB) and an OOM score of -900. You can still log in and
     manage a host whose workloads are out of memory.
   - **Plugin services** live in `/sys/fs/cgroup/ziro/workloads`, with an OOM score of +300, so the kernel reclaims
     or kills them first.
2. **Limits.** Plugins and apps declare `resources`. The limit is enforced by the kernel inside that service or
   container only, and the rest of the host isn't affected. `memory.high` (90% of the limit) throttles and
   reclaims before `memory.max` kills. The limit covers swap too (zram on small hosts), so a
   service can't grow past it into swap:
   ```json
   "resources": {"memory": "1Gi", "cpus": 1.5, "pids": 512}
   ```
   - For cluster apps, set the limit with `ziroctl cluster deploy --memory 2Gi --cpus 1`.
   - A container without a memory limit gets a positive OOM score. It doesn't inherit containerd's protected one.
3. **Admission.** A plugin that declares `min_memory_mb` is refused unless that much memory is actually
   *available*, not just installed (`--force` overrides).
4. **Pressure watchdog.** The sentinel watches the kernel's memory pressure (PSI). When tasks stall on memory for
   15 seconds, it:
   - sends a `memory` alert with the largest consumers
   - restarts the largest plugin service, which turns a thrashing host into a controlled restart

   The settings live in `/etc/ziro/sentinel.json` (defaults shown):
   ```json
   {"memory_full_percent": 10, "memory_for_seconds": 15, "restart_workloads": true, "disk_prune_percent": 90}
   ```
5. **zram swap and reclaim headroom.**
   - On hosts with 8 GiB of RAM or less, ziro-init enables zstd-compressed swap in RAM (25% of RAM), so a short
     spike costs some CPU instead of a killed process. `touch /etc/ziro/zram.disabled` turns it off.
   - `vm.min_free_kbytes` is set to 1% of RAM, so the kernel reclaims before allocations stall.
6. **Bounded tmpfs.** `/tmp` is capped at 25% of RAM, `/run` at 10% and `/dev/shm` at 25%. In live mode the root is
   capped at 75%, so filling a RAM-backed filesystem can't take the whole host down.

## Keeping `ziroctl` current: `ziroctl update`

`ziroctl` and `ziropkg` ship on their own release stream, so fixes reach hosts without an OS upgrade. Tools versions
are `x.y.z` or `x.y.z.N`, where `N` counts the tools-only builds of `x.y.z` (see
[upgrade.md](upgrade.md#tools-only-versions)). Every OS release tag also publishes the matching `tools/vX.Y.Z`;
tools-only fixes ship as `tools/vX.Y.Z.N` and never need a new OS version.

```sh
ziroctl update --check     # also runs daily from cron; the login summary shows the result
ziroctl update             # install the newest compatible release
ziroctl update --version v1.0.21.3
ziroctl update --version v1.0.17 --allow-downgrade   # older than the running version: refused without the flag
ziroctl update --rollback  # back to the binaries the last update replaced
```

- A release is installed only if its `SHA256SUMS` carries a valid Ziro release signature (ed25519; the public key
  is built into `ziroctl`) and every binary matches it.
- A release that needs a newer OS is refused.
- The binaries are swapped atomically. The running ziroctl daemons (API, gateway, sentinel, cluster) are then
  restarted onto the new version, one at a time.
- The integrity baselines (IMA and file integrity) are updated, so the new binaries aren't reported as tampering.
- To install updates automatically, set `{"auto": true}` in `/etc/ziro/update.json`.
- With the API: `GET /api/v1/system/update` (`?refresh=true` checks now) and `POST` (admin) to install.

An OS upgrade (`ziroctl upgrade`, see [upgrade.md](upgrade.md)) keeps a `ziroctl` that is newer than the image's.

### Shell completion

Completions for `ziroctl` are installed in `/usr/share/bash-completion/completions` and
`/usr/share/zsh/site-functions`, and `ziroctl update` refreshes them. The default shell (BusyBox ash) has no
programmable completion. Install bash or zsh to use them:

```sh
ziropkg install bash bash-completion   # then run bash
```

Packages installed with `ziropkg install` are recorded in `/etc/ziro/packages` and reinstalled at boot after
an OS upgrade.
