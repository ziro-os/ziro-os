# Kernel

Ziro-OS has two kernel flavors (see [docs/building.md](../docs/building.md#-kernel-flavors)):

- `custom` (default): built by `build-kernel.sh` from kernel.org LTS sources, using the upstream arch `defconfig` plus:
  - `configs/ziro-common.config`: containers, networking, filesystems, cloud/hypervisor drivers, hardening
  - `configs/ziro-x86_64.config`, `configs/ziro-arm64.config`: arch-specific options
- `alpine`: Alpine `linux-virt`, installed together with its modules by `packages/build-rootfs.sh` (fallback).

```bash
./kernel/build-kernel.sh x86_64                  # -> build/kernel-custom-x86_64/{vmlinuz,modroot,config}
CONFIG_ONLY=1 ./kernel/build-kernel.sh x86_64    # verify the fragments only (about a minute)
```

The build fails if any requested option does not survive `olddefconfig`, or if a boot-critical
driver (virtio/NVMe/AHCI/Hyper-V/Xen storage, ext4, serial console, initramfs support) ends up as a module.

## Build speed

- The build is skipped when `build/kernel-custom-<arch>/stamp` matches the hash of the config fragments,
  `build-kernel.sh`, the kernel version and the toolchain image (`FORCE_KERNEL_BUILD=1` rebuilds).
- `ccache` (`build/ccache-<arch>`) and the verified tarball cache (`build/dl`) make a rebuild after a
  config change much faster. CI keeps both, and the built kernel, in `actions/cache`.
- `sha256sums.asc` must carry a valid signature from the kernel.org checksum autosigner
  (fingerprint pinned in `build-kernel.sh`).

## Security defaults

- **Lockdown `integrity` (forced):** no unsigned modules, kexec images or hibernation images, and no
  `/dev/mem`, `/dev/port`, ioperm or MSR writes.
- **LSMs:** `lockdown,yama,landlock,ima,bpf`. The kernel is built with BTF, so CO-RE eBPF tools run
  unmodified: Cilium, Falco, Tetragon, bpftrace.
- **Memory and kernel hardening:**
  - stack protector, FORTIFY, hardened usercopy, `LIST_HARDENED`, `BUG_ON_DATA_CORRUPTION`
  - **init-on-alloc and init-on-free**: freed memory is zeroed. Opt out per host with `init_on_free=0`.
  - freelist hardening and randomization, randomized kmalloc caches, kstack offset randomization,
    `ZERO_CALL_USED_REGS`, no slab merging
  - page table checks, stack-end checks, KFENCE (sampling heap error detector)
  - `dmesg` restricted, no TIOCSTI, and no line discipline autoload
- **Removed attack surface:** kexec, hibernation, SysRq, `/dev/port`. On x86, `ioperm`/`iopl` too.
  - Kept on purpose: `userfaultfd` (limited to root by sysctl) for CRIU, and `binfmt_misc` (module) for
    multi-arch builds.
  - arm64 kernel BTI and shadow call stacks need a clang build and are not enabled.
- **Integrity:**
  - IMA, with the policy loaded by the `integrity` module.
  - fs-verity.
  - fanotify permission events, used by `clamav-onaccess`.
- **Modules:**
  - Modules are signed (`MODULE_SIG_FORCE`) and zstd-compressed.
  - Release kernels sign with the persistent Ziro key. It is the CI secret `ZIRO_MODULE_SIGNING_KEY`, and its
    public certificate is `certs/ziro-modules.crt`. Modules built later by Ziro CI therefore still load.
  - A local build without the secret uses an ephemeral key, and a wrong secret fails the build.
  - `ZIRO_EXTRA_TRUSTED_CERT=<pem>` builds a kernel that also trusts modules signed by your key (your own
    kernel; official builds never set it).
- **Kernel kit:** every build also packs `kernel-devel.tar.gz` (released as `kernel-devel-<arch>.tar.gz`): the
  headers, scripts and `Module.symvers`, `vmlinux.h` and the signing certificate, for `ziroctl dev kmod|bpf
  build` ([SDK](../docs/sdk.md#kernel-modules-and-ebpf)).

## Performance defaults

- **Congestion control:** BBR, with the fq qdisc for pacing, on every socket. The sysctls in
  `rootfs/etc/sysctl.d/99-ziro.conf` also set deep accept queues and a wide port range for gateways.
- **Networking features:** MPTCP, kernel TLS, and nftables flowtables (the fast path for established forwarded
  flows).
- **Memory:** transparent huge pages only on `madvise`, so databases don't hit khugepaged stalls. zswap is
  available.

## Boot

Installed hosts boot a tiny initramfs (`/boot/initramfs-boot.cpio.gz`, about 6 MB). It holds
ziro-init, BusyBox, kmod, e2fsck and the storage modules. It waits for `root=` (up to
`rootwait=`, default 90 s), runs `e2fsck -p`, mounts `rootfstype=` (default ext4) and switches
root. A missing or broken root disk never falls back to the live image: the host reboots after
30 s. The `Ziro-OS (Recovery Shell)` GRUB entry (`ziro.recovery`) is the break-glass path.
