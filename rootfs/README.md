# Root filesystem overlay

Files that `packages/build-rootfs.sh` copies into the Ziro OS host image on top of the Alpine, musl and BusyBox
userland.

## Contents

- `etc/`: configuration for init, services, networking, containerd, CNI, SSH, sysctl, PAM and the firewall defaults.
- `usr/`: small helper executables (`systemctl` and `docker-compose` compatibility shims, `ziro-motd`).

The standard directories (`bin/`, `sbin/`, `lib/`, `var/`, `tmp/`) are populated by the build from Alpine packages and
BusyBox; they are not tracked here.

## Build

The root filesystem is assembled by `make rootfs` using musl libc and BusyBox. See [building](../docs/building.md).
