# Ziro-OS System Architecture

Ziro-OS is a cloud-native, ultra-lightweight operating system engineered from first principles specifically to host container workloads. It dispenses with the bloat of general-purpose distributions while preserving full compatibility with Open Container Initiative (OCI) runtimes, `containerd`, and Docker-compatible workflows.

---

## 1. Core Architectural Tenets

```
+-----------------------------------------------------------------------+
|                       Container Workloads (OCI)                       |
+-----------------------------------------------------------------------+
|                    containerd + runc + CNI Plugins                    |
+-----------------------------------------------------------------------+
|           ziroctl (Management CLI) & System Daemon Layer              |
+-----------------------------------------------------------------------+
|         ziro-init (High-Performance C99 PID 1 Supervisor)             |
+-----------------------------------------------------------------------+
|               Unified cgroups v2 Hierarchy & Namespaces               |
+-----------------------------------------------------------------------+
|    Linux LTS Kernel (VirtIO, Netfilter, Seccomp, Namespaces, OverlayFS)|
+-----------------------------------------------------------------------+
|             Hardware / Hypervisor (QEMU, KVM, Cloud, Bare Metal)      |
+-----------------------------------------------------------------------+
```

1. **Minimal Base**: Sub-10MB base container rootfs, ~50MB full host initramfs.
2. **Stateless & Immutable**: Immutable root filesystem with minimal writeable paths (`/run`, `/tmp`, `/var/lib/containerd`).
3. **Container-Native**: Built-in `containerd`, `runc`, and CNI networking.
4. **Multi-Architecture**: First-class support for `x86_64` (Intel/AMD) and `arm64` (Apple Silicon & ARM servers).
5. **Instant Boot**: Optimized for sub-second microVM boot times in modern hypervisors (QEMU, AWS Firecracker, Cloud-Hypervisor).

---

## 2. PID 1 Supervisor (`ziro-init`)

Traditional Linux distributions rely on heavy init systems (such as `systemd` or SysV init) that introduce extensive service graphs, dynamic library overhead, and hundreds of background processes.

Ziro-OS utilizes `ziro-init`, a self-contained, statically compiled C99 supervisor designed specifically for container hosts:

- **Early Mounts**: Automatically mounts `/proc`, `/sys`, `/dev` (devtmpfs), `/dev/pts`, `/dev/shm`, `/run` (tmpfs), and `/tmp` (tmpfs 1777).
- **Cgroups v2 Initialization**: Mounts `cgroup2` on `/sys/fs/cgroup` with `nsdelegate` and auto-enables all available controllers (`+cpu +memory +io +pids`) in `cgroup.subtree_control`.
- **Network Bootstrap**: Brings up the loopback interface (`lo`) and initializes routing parameters.
- **Kernel Sysctl Hardening**: Applies container forwarding and memory management optimizations.
- **Containerd Supervision**: Starts and supervises the `/usr/bin/containerd` daemon, verifying socket readiness at `/run/containerd/containerd.sock`.
- **Zombie Reaping**: Reaps terminated child processes in a non-blocking `waitpid(-1, &status, WNOHANG)` loop to prevent PID table starvation.
- **Graceful Shutdown**: Intercepts `SIGTERM`, `SIGINT`, and `SIGPWR` to cleanly terminate container workloads, sync storage, and unmount filesystems before poweroff or reboot.

---

## 3. Container Runtime Stack

Ziro-OS implements standard OCI specifications:

- **`containerd`**: Core container runtime managing image transfer, snapshotting, and task execution.
- **`runc`**: Low-level OCI runtime executing containers using kernel namespaces and cgroups.
- **`cni-plugins`**: Standard container networking plugins including `bridge`, `loopback`, `host-local`, `portmap`, and `firewall`.
- **`ziroctl`**: Official management CLI providing declarative commands for container lifecycle, system status, network inspection, and security auditing.

---

## 4. Multi-Architecture Support Matrix

| Architecture | Kernel Image | Console | Primary Hypervisors / Platforms |
|---|---|---|---|
| **x86_64** (amd64) | `vmlinuz-x86_64` (bzImage) | `ttyS0`, `tty0` | QEMU, KVM, VMware, VirtualBox, Proxmox, AWS EC2, GCP Compute |
| **arm64** (aarch64) | `vmlinuz-arm64` (Image) | `ttyAMA0`, `tty0` | Apple Silicon (QEMU HVF), AWS Graviton, Ampere Altra, Raspberry Pi |
