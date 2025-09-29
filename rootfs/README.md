# Root Filesystem

Minimal userland root filesystem for Ziro-OS.

## Structure
- `etc/` - Configuration files (init, services, networking)
- `bin/` - Essential executables (busybox, core tools)
- `sbin/` - System binaries
- `lib/` - Libraries (musl libc)
- `usr/` - User programs and libraries
- `var/` - Variable data (logs, containers)
- `tmp/` - Temporary files

## Build
The rootfs is built using musl libc and BusyBox for minimal footprint.