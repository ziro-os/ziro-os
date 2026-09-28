# Kernel

Ziro-OS has two kernel flavors (see [docs/building.md](../docs/building.md#-kernel-flavors)):

- `alpine` (default): Alpine `linux-virt`, installed together with its modules by `packages/build-rootfs.sh`.
- `custom`: built by `build-kernel.sh` from kernel.org LTS sources, using the upstream arch `defconfig` plus:
  - `configs/ziro-common.config`: containers, networking, filesystems, cloud/hypervisor drivers, hardening
  - `configs/ziro-x86_64.config`, `configs/ziro-arm64.config`: arch-specific options

```bash
KERNEL_FLAVOR=custom ./kernel/build-kernel.sh x86_64   # -> build/kernel-custom-x86_64/{vmlinuz,modroot,config}
```

The build fails if any requested option does not survive `olddefconfig`.
