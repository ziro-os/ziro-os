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

## Secure Defaults (v1.0.10)

- **Console login**: installed systems always require `login` on tty1/ttyS0/ttyAMA0. A locked or empty root
  password means no console login. An unauthenticated root shell exists only on the live ISO, or with the exact
  `ziro.recovery` kernel argument. Anyone who can pick the GRUB "recovery" entry gets root, so set a GRUB
  password on shared consoles.
- **Cloud access**: the `cloud-init` service (autostart) uses IMDSv2 to install instance SSH keys into
  `/root/.ssh/authorized_keys` and runs shell user-data once per instance. It only trusts `169.254.169.254` on
  EC2-compatible clouds detected by DMI (override with `touch /etc/ziro/cloud-init.force`).
- **Services**: `ziro-init` starts every enabled service (`ziroctl service boot`), so the firewall and Sentinel
  are active from boot. A service's PID is only signalled when its argv matches the service definition.
- **Firewall**: rules live in their own `inet ziro` nftables table. CNI, nerdctl, WireGuard and kube-proxy rules
  are never flushed. ICMP/ICMPv6 are allowed, and so is SSH (22). Inputs are validated, and nft errors are reported.
- **REST API**: binds `127.0.0.1:8443` by default, CORS is off, and the token is checked in constant time and never
  logged. To expose it: `ziroctl api start --bind 0.0.0.0` plus `ziroctl firewall allow 8443`.
- **Sentinel**: alert-only by default. Use `ziroctl security monitor --enforce` to SIGKILL CRITICAL detections.
  File integrity is checked against a baseline in `/etc/ziro/fim.db`. Refresh it after upgrades with
  `ziroctl security harden`.
- **Backups**: archives are root-only (0600) and unencrypted, and they contain private keys. Restore rejects
  paths outside the backup allowlist, traversal, hardlinks, and writes through symlinks.
- **Clustering**: joins use a pinned master certificate plus a join token, and each node gets its own token (the
  master stores only hashes). See [clustering.md](clustering.md).
- **Kernel & sysctl**: the `custom` kernel flavor enforces module signing (ephemeral per-build key; unsigned modules are rejected). Its config fragments add KASLR, strict RWX, a strong stack protector, hardened
  usercopy, FORTIFY, the Yama and lockdown LSMs, unprivileged BPF off, and nftables/WireGuard built in. Shipped
  sysctls set `kptr_restrict=2`, `dmesg_restrict=1`, `unprivileged_bpf_disabled=1`, `ptrace_scope=1`, protected
  links/fifos/regular files, and loose `rp_filter=2` (strict mode breaks WireGuard and multi-homed routing).
- **Logs**: crond runs `ziroctl service rotate-logs` hourly. It copies and truncates any `/var/log/*.log` over
  10MB, and Sentinel only logs when the alert set changes.
- **CI supply chain**: every GitHub Action is pinned to a commit SHA and each workflow gets least-privilege
  `permissions`. Cloud image builds use OIDC once the `AWS_ROLE_ARN` or `GCP_WIF_PROVIDER` + `GCP_SERVICE_ACCOUNT`
  repo variables are set. After that, delete the static key secrets.
- **Terraform (AWS)**: IMDSv2 is required with hop limit 1. SSH is limited to `ssh_allowed_cidrs`, which is
  required. Bootstrap scripts come from the pinned `ziro_version` tag, with optional sha256 verification.
