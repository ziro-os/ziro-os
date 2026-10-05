# Packages

How the host and base filesystems are assembled.

- `build-rootfs.sh` builds both images inside Docker: the minimal container base (`ziro-rootfs-<arch>.tar.gz`) and
  the full host initramfs (Alpine packages: containerd, runc, CNI, nftables, OpenSSH, e2fsprogs, WireGuard
  tools...). `make rootfs TARGET_ARCH=arm64` runs it; see [building](../docs/building.md).
- `base/*.yaml` record the pinned components of the minimal base (musl, BusyBox, containerd, runc, CNI).
- `cni-dhcp/` rebuilds the CNI DHCP plugin against patched dependencies; see its README.

Optional software is never added here. It ships as a [plugin](../docs/modules.md) instead, so the base stays small.
