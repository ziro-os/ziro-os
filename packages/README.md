# Packages

How the host and base filesystems are assembled.

- `build-rootfs.sh` builds both images inside Docker: the minimal container base (`ziro-rootfs-<arch>.tar.gz`) and
  the full host initramfs (Alpine packages: containerd, runc, CNI, nftables, OpenSSH, e2fsprogs, WireGuard
  tools...). `make rootfs TARGET_ARCH=arm64` runs it; see [building](../docs/building.md).
- `base/*.yaml`, `Makefile` and `build-package.sh` are legacy recipes for the base components (musl, BusyBox,
  containerd, runc, CNI). The build does not read them: component versions come from the Alpine release set by
  `ALPINE_IMAGE`, and the recipes' versions are out of date.
- `cni-dhcp/` rebuilds the CNI DHCP plugin against patched dependencies; see its README.

Optional software is never added here. It ships as a [module](../docs/modules.md) instead, so the base stays small.
