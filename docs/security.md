# Ziro-OS Security & Hardening Model

Security is a foundational design pillar of Ziro-OS. Unlike general-purpose distributions that run dozens of background daemons, cron jobs, and SSH servers by default, Ziro-OS eliminates non-essential attack surfaces.

---

## 🔒 Security Principles

### 1. Minimal Attack Surface
- No extraneous services, package managers, or compilers on the host OS.
- Only essential container runtimes (`containerd`, `runc`) and the `ziro-init` supervisor are installed.

### 2. Immutable Root Filesystem
- The base rootfs is mounted read-only in production.
- Only designated tmpfs paths (`/run`, `/tmp`) and dedicated container storage (`/var/lib/containerd`) are writable.

### 3. Unified cgroups v2 & Namespaces
- Enforces strict resource limits (CPU quotas, memory caps, PID exhaustion limits) using cgroup2 subtree controllers.
- Complete isolation via Linux namespaces (`pid`, `net`, `ipc`, `uts`, `user`, `mnt`).

### 4. Kernel Seccomp & Capability Restrictions
- Kernel configurations explicitly enable `CONFIG_SECCOMP` and `CONFIG_SECCOMP_FILTER`.
- Default capability restrictions prevent unprivileged containers from accessing host devices or performing raw network modifications.

### 5. Network Hardening (Sysctl)
Configured in `/etc/sysctl.d/99-ziro.conf`:
- `net.ipv4.conf.all.forwarding = 1`: Controlled IP forwarding for CNI bridge networks.
- `net.bridge.bridge-nf-call-iptables = 1`: Netfilter packet filtering across container bridges.
- Automatic recovery parameters (`kernel.panic = 10`, `kernel.panic_on_oops = 1`).

---

## 🛡️ Running Security Audits

Verify system hardening in real-time using `ziroctl`:

```bash
ziroctl security audit
```
Output:
```
=== Ziro-OS Security & Hardening Audit ===
 [PASS] Kernel Seccomp Support
 [PASS] Namespaces Enabled (pid, net, ipc, uts, user, mnt)
 [PASS] Unified cgroups v2 Hierarchy
 [PASS] Container IPv4 Forwarding Enabled
 [PASS] /tmp sticky bit configured correctly
```
