# Kernel

Ziro-OS has two kernel flavors (see [docs/building.md](../docs/building.md#-kernel-flavors)):

- `alpine` (default): Alpine `linux-virt`, installed together with its modules by `packages/build-rootfs.sh`.
- `custom`: built by `build-kernel.sh` from kernel.org LTS sources, using the upstream arch `defconfig` plus:
  - `configs/ziro-common.config`: containers, networking, filesystems, cloud/hypervisor drivers, hardening
  - `configs/ziro-x86_64.config`, `configs/ziro-arm64.config`: arch-specific options

```bash
KERNEL_FLAVOR=custom ./kernel/build-kernel.sh x86_64   # -> build/kernel-custom-x86_64/{vmlinuz,modroot,config}
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

- Lockdown `integrity` (forced): no unsigned modules, kexec images or hibernation images, and no
  `/dev/mem`, `/dev/port`, ioperm or MSR writes.
- LSMs: `lockdown,yama,landlock,bpf`. The kernel is built with BTF, so CO-RE eBPF tools run
  unmodified: Cilium, Falco, Tetragon, bpftrace.
- Hardening: stack protector, FORTIFY, hardened usercopy, init-on-alloc, freelist hardening and
  randomization, `LIST_HARDENED`, `BUG_ON_DATA_CORRUPTION`, randomized kmalloc caches, kstack offset
  randomization, `ZERO_CALL_USED_REGS`, no slab merging, `dmesg` restricted, no TIOCSTI, and no line
  discipline autoload. (arm64 kernel BTI needs a clang build and is not enabled.)
- Modules are signed (`MODULE_SIG_FORCE`) and zstd-compressed.

## Boot

Installed hosts boot a tiny initramfs (`/boot/initramfs-boot.cpio.gz`, about 6 MB). It holds
ziro-init, BusyBox, kmod, e2fsck and the storage modules. It waits for `root=` (up to
`rootwait=`, default 90 s), runs `e2fsck -p`, mounts `rootfstype=` (default ext4) and switches
root. A missing or broken root disk never falls back to the live image: the host reboots after
30 s. The `Ziro-OS (Recovery Shell)` GRUB entry (`ziro.recovery`) is the break-glass path.
