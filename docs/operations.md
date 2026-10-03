# Operating a host

Day-to-day commands for keeping a Ziro OS host healthy: what it shows at login, what uses it,
reclaiming disk, how it protects itself from running out of memory, and keeping `ziroctl` current.

## Login summary

Every login (and the boot console) shows a short summary, from `ziroctl motd`:

```
 Ziro OS 1.0.17  web-1  installed  Proxmox VE  x86_64  kernel 6.18.54-ziro
 Resources  2 vCPU  load 0.42  memory 2.5 GiB/3.9 GiB (64%)  disk / 41%
 Network    172.26.1.108 (eth0)  mesh 10.200.0.1  pods 10.201.0.1
 Workloads  5 containers  cluster master 3/3 nodes ready  api off
 Attention  memory pressure 12%  ·  clamav killed 2x for memory  ·  ziroctl 1.1.0 available
```

- **Network** lists each address once. The default-route interface comes first, then other NICs, the cluster mesh
  (`mesh`) and the pod gateway (`pods`). Container interfaces aren't shown.
- **Attention** appears only when something needs you. It flags:
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

There are two panes:
- **Containers** (`c`): CPU, memory against its limit, network and block I/O rates, and PIDs. It's read straight
  from each container's cgroup, like `docker stats`.
- **Processes** (`p`): PID, user, CPU, RSS, state, and the service or container each one belongs to.

Keys:
- `s` cycles the sort (CPU, memory, name).
- `/` filters.
- `k` stops the top row, after asking.
- `q` quits.

It reads `/proc` and cgroup files directly; the only subprocess is an occasional name lookup. That keeps it light
on a busy host.

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
- images no container uses
- rotated logs
- temp files in `/tmp` and `/var/tmp` older than 7 days that no process has open
- the package cache
- the upgrade rollback generation, with `--all` only (after that, the last upgrade can't be rolled back)

App data, volumes, secrets and `/etc` are never touched.

Logs over 10 MB are rotated hourly, keeping 3 gzip-compressed generations (`<log>.1.gz` is the newest).

When `/var` reaches 90%, the sentinel prunes images, rotated logs, stale temp files and caches on its own, and
sends a `disk` alert saying what it freed. The threshold is `disk_prune_percent` in `/etc/ziro/sentinel.json`; `0`
turns this off.

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

`ziroctl` and `ziropkg` ship on their own release stream (`tools/vX.Y.Z`), so fixes reach hosts without an OS
upgrade. Every OS release tag also publishes the matching tools release, and hotfixes can ship as their own
`tools/vX.Y.Z` tag.

```sh
ziroctl update --check     # also runs daily from cron; the login summary shows the result
ziroctl update             # install the newest compatible release
ziroctl update --version v1.0.17
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
ziroctl pkg install bash bash-completion   # then run bash
```

Packages installed with `ziroctl pkg install` are recorded in `/etc/ziro/packages` and reinstalled at boot after
an OS upgrade.
