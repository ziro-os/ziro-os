# Base OS review: size, boot cost and attack surface

A review of how lean and how hardened the base OS is, done while adding the optional [Tailscale module](../tailscale.md)
([RFC 0003](rfcs/0003-tailscale-module.md)). It is a reading of the source tree, not a measurement: there was no built
image to inspect, so every size below is either a figure the repository already states or an estimate marked as one, with
the command that measures it. Each finding says whether it is **applied** in the pull request that added this page,
**measure first**, or **not applied** and why. The goal it is judged against is the one in `AGENTS.md`: minimal by design,
every bootable image under 300 MB (enforced in CI), nothing optional in the base.

## What is already right

- **Optional software is a module.** `packages/README.md` states it and the Tailscale module follows it: nothing is added
  to the base, the binaries come from the signed catalog on demand. The base needs no change to host it, and the kernel
  already has what it needs (`TUN=y`, policy routing, `NF_TABLES`/`NFT_COMPAT`/`NFT_NAT`/`NFT_MASQ`/`NFT_CT`,
  `NETFILTER_XT_MARK`; module signing is no obstacle because tailscaled brings its own userspace WireGuard).
- **Small boot path for installed hosts.** A ~6 MB tiny initramfs (`kernel/README.md`) mounts the real root; the full image
  is only the live ISO.
- **Compressed, stripped, signed kernel modules**, `MODULE_SIG_FORCE=y`, lockdown integrity, init-on-alloc/free, KFENCE,
  no kexec/hibernation/SysRq, LSMs `lockdown,yama,landlock,ima,bpf` (`kernel/configs/ziro-common.config`).
- **Memory design.** Service cgroups (`ziro/system`, `ziro/workloads`), OOM classes, `memory.min` for the platform,
  zram, bounded `/tmp` and `/run`, and a `GOMEMLIMIT`/`GOGC` default for ziroctl-family daemons.
- **Firewall before the network.** `inet ziro` (input policy drop) is applied before containerd and sshd start; only sshd
  listens externally at boot.
- **Hardening defaults.** `rootfs/etc/sysctl.d/99-ziro.conf` (`kptr_restrict=2`, `unprivileged_bpf_disabled=1`,
  `io_uring_disabled=1`, `kexec_load_disabled=1`, `rp_filter=2`), sshd keys-only with strong ciphers, root locked,
  `trustedExecutable`/`rootOwnedFile` checks on every service definition.

## Size

Repository figures: the minimal container base is about 16 MB (compressed), the live OS image about 160 MB, the tiny boot
initramfs about 6 MB. The 300 MB gate applies to the compressed `.iso` and `.cpio.gz` only: not installed size, not RAM.

| Finding | Status |
|---|---|
| The ISO carried a second copy of the minimal rootfs (`ziro/rootfs.tar.gz`, ~16 MB) that nothing reads (`images/iso/build-iso.sh`). It is a separate release asset already. | **Applied** (-16 MB on the ISO) |
| `/opt/cni/bin` is a full copy of `/usr/libexec/cni` (`build-rootfs.sh`, `cp -r`), and cpio+gzip does not deduplicate: every CNI plugin ships twice. The conflist uses six of Alpine's ~20 plugins. Likely the largest single item. | **Measure first.** A symlink breaks the integrity baseline (it lists files under `opt/cni/bin`) and `tests/security/test-cni-dhcp.py` (checks both paths); hard links need the upgrade code's cpio reader to handle them. Prune to the plugins in use instead, after `du` shows the saving. |
| `e2fsprogs-extra` is installed and `resize2fs` is required to exist, but the disk grow is done with the kernel's resize ioctl (`diskresize_linux.go`). | **Measure first**: `apk info -L e2fsprogs-extra` for what else it provides. |
| `parted` is installed for `partprobe` in the installer (`ziro-install.sh`). `blockdev --rereadpt` or `sfdisk` would do. | Not applied: installer behaviour change. |
| `linux-pam` and `/etc/pam.d/*`: BusyBox `login` has no PAM and Alpine's plain `openssh-server` is built without it. | Not applied: verify with `apk info -R openssh-server` first. |
| `wireguard-tools` brings `wg-quick`, which pulls in bash. The code already falls back to `ip`/`wg setconf` (`wireguard.go`). | Not applied: the boot smoke test uses bash process substitution (`/dev/fd`), so removing bash needs a decision about the console shell first. |
| Installer-only tools (`grub-bios`, `grub-efi`, `sfdisk`, `dosfstools`, `parted`, `mkfs.ext4`) are in the live image and the installed rootfs. About 15-25 MB uncompressed (estimate). | Not applied: could be an ISO-only initrd overlay (GRUB accepts several initrds and cpio archives concatenate). |
| `/boot/vmlinuz` is in the initramfs and the ISO carries the same kernel again. | Not applied: the installer's fallback path needs a change first. |
| Both `nftables` and `iptables` are installed. `ziroctl` uses `nft` for everything; `iptables` (routed to xtables-nft) is for the CNI plugins. | Keep both. |
| `packages/base/*.yaml`, `packages/Makefile` and `build-package.sh` are stale (runc 1.1.9, containerd 1.7.8) and unused by the build. | Not applied: repository hygiene, no effect on size. Delete when convenient. |
| The minimal base is ~16 MB because it carries the Go binaries: `ziroctl` links wireguard-go, quic-go, raft+bolt, go-tpm and oidc. A container base does not need that. | Design question: a smaller `ziropkg`-only base, or build tags. |

To measure on a built tree:

```sh
du -xk build/rootfs-full-x86_64-custom/{usr,lib,boot,opt,sbin,bin}/* | sort -n | tail -40
apk --root build/rootfs-full-x86_64-custom info -s '*' | paste - - - | sort -k3 -n | tail
```

**Gates.** `kernel-custom.yml` skipped a missing artifact (`[ -f "$f" ] || continue`), so the size gate passed when
nothing was built: **applied**, it now fails. CI also writes the size of the ISO, initramfs and rootfs to the run summary
so growth is visible in review. A budget for the minimal base is not set: the only check is a Docker image warning at
30 MB (`tests/smoke/test-docker-base.sh`) and it never fails; pick the number after the first measurements.

## Boot path and runtime

- Boot (`init/ziro-init.c`): tiny initramfs (`check_and_switch_root`, device init, `e2fsck -p`), then init again
  (`init_devices` a second time, cgroups, network, memory tuning, early firewall, containerd, sshd, enabled services).
- ~50 named modules are modprobed at boot, many built in; coldplug runs `modprobe -qa` on every modalias under `/sys/devices`
  with no blacklist, so bare metal loads GPU, sound and WLAN drivers.
- The critical path waits: up to 60 s for housekeeping in `ziroctl service boot` (disk expand, `reconcileModules`, which
  can be an apk reinstall over the network, NFS), 1 s per supervised daemon, up to 5 s for the host summary, up to 3 s for
  containerd's socket. Login terminals start after all of it. This is the likely source of the ~53 s "boot to live init"
  under emulation in the smoke test; no number or budget exists in the repo (`docs/project-goals.md`: no boot-time guarantee).
- About 7 `system("sysctl …")` forks in `init_network`; first boot runs `ssh-keygen -A` (RSA is the slow one, sshd uses
  ed25519 and RSA).
- Always running: containerd, sshd, crond, sentinel (30 s scan, 2 s guard poll, 5 s watchdog). Idle wakeups: init polls
  every 250 ms, `heal_tick` forks the Go binary every 15 s then 60 s, cron forks `ziroctl disk expand --auto` every minute.

None of this is applied here: each changes the boot path and needs a boot-time measurement first. Recommended order:
measure (add a boot-time and idle-RSS number to the smoke test), move the ready marker and console ahead of housekeeping,
skip the second coldplug pass and add a modprobe blacklist, generate only the needed host keys, replace the 250 ms poll and
the per-minute cron fork with in-init checks, consider disabling containerd's CRI plugin if nothing needs it.

## Attack surface and privilege

Gaps, most important first:

1. **No privilege reduction for host daemons.** Nothing in `tools/` used capabilities, `no_new_privs`, seccomp or
   Landlock, although Landlock and the BPF LSM are enabled in the kernel. sshd, containerd, sentinel, gateway, ziro-api,
   router-* and cloud-init run as root with a full capability set; the network-facing ones parse untrusted input.
   *Progress:* [RFC 0003](rfcs/0003-tailscale-module.md) adds `caps` for services (a non-root user keeping only the listed
   capabilities, `no_new_privs`), used first by tailscaled. Next: move gateway, router-relay/moon and ziro-api to it, then
   Landlock.
2. **The firewall covers input only.** `inet ziro` has no forward chain, `ip_forward=1` is set before the firewall is
   applied, and published container ports reach the host through DNAT/FORWARD, so they bypass `ziroctl firewall`
   (`--bind 0.0.0.0` exposes them). *Not applied:* a forward policy changes container networking.
3. **sshd's OOM protection is documented but not implemented**: `docs/operations.md` says -900; init never writes
   `oom_score_adj` for the daemons it spawns directly (sshd). *Not applied:* small init change, wants the boot test.
4. **Writable root and permissive mounts.** ext4 root is `rw`; `/tmp`, `/dev/shm`, `/run` are nosuid,nodev but not noexec.
5. **IMA is measure-only and opt-in** (the `integrity` module): no appraisal, baseline writable by root.
6. **Recovery path**: GRUB always has a "Recovery Shell" entry and no GRUB password.
7. **No time sync** (BusyBox `ntpd` exists, not enabled): matters for TLS, tokens, Raft and ACME on bare metal.
8. **sshd** listens on all addresses and sets no `DisableForwarding`/`AllowTcpForwarding`/`PermitTunnel`. *Not applied:*
   disabling forwarding changes what admins can do over SSH.
9. Defaults worth revisiting: resolver hard-codes 8.8.8.8/1.1.1.1; 51820/udp is open even when WireGuard is off.

Cheap and low-risk when someone can run the boot test: noexec on `/tmp` and `/dev/shm`, `oom_score_adj` for sshd, 51820/udp
only when WireGuard is configured, `ntpd`.

## Kernel configuration

The x86_64 fragment trims nothing from the defconfig (the arm64 one drops SOUND, WLAN, BT, MEDIA, Nouveau and MSM), so x86
builds sound, Bluetooth, WLAN and DRM drivers as modules: copy the arm64 block over. `DEBUG_INFO_BTF_MODULES=y` adds BTF to
every module (vmlinux BTF is what CO-RE needs). Legacy xtables (`NETFILTER_XTABLES_LEGACY`, `IP_NF_IPTABLES_LEGACY`) are
unused by the base, which routes through xtables-nft, and are classic attack surface. IPVS, NFS, XFS, BTRFS, VXLAN, KVM and
more are `=m`: they cost disk, not RAM, and could move to an extra-modules overlay to stay inside 300 MB as the base grows.
Not applied: kernel changes need the full kernel build and boot matrix.

## Tailscale

Needs nothing from the base. Optional extras, only if the module grows: `ethtool` (UDP GRO on subnet routers and exit nodes)
and `CONNMARK` support, both for features the first version does not offer.

## What the pull request that added this page changes

- The ISO no longer carries the unused second copy of the minimal rootfs (~16 MB).
- The kernel workflow's size gate fails when an artifact is missing; CI prints artifact sizes on the run summary.
- This page.

Everything else above is a recommendation with the measurement that should come first.
