# Ziro-OS Security & Hardening Model

Security is a foundational design pillar of Ziro-OS. Unlike general-purpose distributions that run dozens of background daemons, cron jobs, and SSH servers by default, Ziro-OS eliminates non-essential attack surfaces.

---

## 🔒 Security Principles

### 1. Minimal Attack Surface
- Full hosts include containerd/runc/CNI, OpenSSH, apk/ziropkg, and enabled host services.
- The minimal container base starts `/bin/sh`; optional API and cluster listeners require configuration.

### 2. Immutable Root Filesystem
- Immutable root is a design target. The current installer mounts ext4 read/write; live boot uses writable tmpfs.
- `/run` and `/tmp` use tmpfs. Deployments requiring immutable root must provide and verify that enforcement.

### 3. Unified cgroups v2 & Namespaces
- PID 1 enables cgroup2 controllers. Every service runs in its own cgroup: platform daemons in `ziro/system`
  (memory reservation, OOM score -900), plugin services in `ziro/workloads` (OOM score +300). Plugins and apps
  declare `resources` (memory, CPUs, PIDs), enforced by the kernel; a sentinel watchdog reacts to sustained memory
  pressure. See [operations](operations.md#memory-how-a-host-protects-itself).
- Namespace and seccomp support must be paired with verified runtime settings; host binds, privileged mode,
  runtime sockets, and host networking grant additional authority. Local `ctr` fallback uses host networking.

### 4. Kernel Seccomp & Capability Restrictions
- Kernel configurations explicitly enable `CONFIG_SECCOMP` and `CONFIG_SECCOMP_FILTER`.
- Runtime policy must restrict capabilities and device access. Verify the effective configuration for each workload.

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
  are active from boot. A service's PID is only signalled when its argv matches the service definition, or, for
  a daemon that rewrites its title (sshd), when its pidfile names a process running that exact binary.
  - `ziro-init` itself supervises containerd and sshd. `ziroctl service stop` leaves a marker in
    `/run/ziro/stopped/`, which holds init's restart, and `start` removes the marker so init respawns the daemon.
  - `restart` validates the config first (`check=` in the definition; sshd uses `sshd -t`). A broken
    `sshd_config` is refused and the running sshd is kept, so a typo can't lock you out.
  - `start` reports a daemon that exits during its first second, instead of claiming success.
- **Firewall**: rules live in their own `inet ziro` nftables table. CNI, nerdctl, WireGuard and kube-proxy rules
  are never flushed. ICMP/ICMPv6 are allowed, and so is SSH (22). Inputs are validated, and nft errors are reported.
- **REST API**: binds `127.0.0.1:8443` by default, CORS is off, and tokens are checked in constant time and never
  logged. To expose it: `ziroctl api start --bind 0.0.0.0` plus `ziroctl firewall allow 8443`.
  - Tokens are scoped: `ziroctl api token create <name> --role viewer|operator|admin [--ttl 90d]` prints the token
    once. Only its SHA-256 is stored (`/etc/ziro/api-tokens.json`, 0600).
  - `viewer` can only read. `operator` can also act (for example, restart a service). `admin` can do everything.
  - Tokens expire (90 days by default). `ziroctl api token ls` lists them and `ziroctl api token revoke` removes one.
  - Every action is audited under the token's name.
  - The pre-RBAC token in `/etc/ziro/api.token` still works as admin; delete the file to disable it.
- **Sentinel**: alert-only by default. Use `ziroctl security monitor --enforce` to SIGKILL CRITICAL detections.
  File integrity is checked against a baseline in `/etc/ziro/fim.db`. Refresh it after upgrades with
  `ziroctl security harden`.
- **Ziro Guard (flood, scan and brute-force protection)**: on whenever the firewall is on
  (`ziroctl security protect status|set|allow|disallow|enable|disable`).
  - It lives in its own `inet ziro_guard` nftables table that firewall changes never delete, so bans keep their
    remaining time and expire in the kernel.
  - Per source address: new TCP connections over 100/s, more than 256 concurrent connections, or ICMP over 20/s
    are dropped.
  - Port scans (SYNs to closed ports over 20/min, with a default-drop firewall) are banned for 10 minutes by the
    kernel itself.
  - Sentinel bans SSH sources after 5 failures in 10 minutes: 1 hour first, doubling for repeat offenders up to 24
    hours. It counts OpenSSH's own PerSourcePenalties lines too, but never penalties for connections that don't
    try to log in (load balancer health checks).
  - The source address is taken from where sshd writes it, so a crafted username cannot frame another address.
  - Banned addresses cannot reach published container ports either.
  - Never limited: loopback, link-local, the cluster mesh (`ziro0`), container bridges and `protect allow` CIDRs.
  - Manage bans with `ziroctl security bans list|ban|unban`, or `GET/POST /api/v1/security/bans` (changes need an
    admin token).
- **Security alerting**: `ziroctl security alerting add <name> --url https://... [--min-severity high]
  [--events ban,threat,fim,canary] [--format json|slack]` pushes Sentinel threats, file-integrity and canary
  changes, and bans to webhooks.
  - Each request is signed: `X-Ziro-Signature: sha256=HMAC-SHA256(secret, X-Ziro-Timestamp + "." + body)`. The
    secret is shown once at creation. Reject stale timestamps to stop replays.
  - Alerts are queued in `/var/lib/ziro/alerts` and retried with backoff for 24 hours. The same alert is sent at
    most once per 10 minutes.
  - Webhooks must be HTTPS (plain HTTP only to loopback), and redirects are not followed.
  - The API (`/api/v1/security/alerting`) is admin-only.
- **Container defaults**: cluster containers run with `no-new-privileges` and without `NET_RAW` (no raw-socket
  spoofing). `cluster deploy --allow-privilege-escalation` opts an app out.
- **SSH key import**: `ziroctl ssh key import gh:<user> [gl:<user>] [lp:<user>]` fetches published keys over HTTPS
  from fixed provider URLs. The username is validated, the response is capped at 64 KB, and redirects are only
  followed on the same host. DSA keys and RSA keys under 2048 bits are rejected, and so are keys with options.
  Keys are deduplicated by fingerprint and tagged `ziro-import:<src>:<user>`. `--sync` also removes keys the user
  deleted upstream, but never syncs to an empty list, so you can't be locked out. `ssh key remove --source
  gh:<user>` removes every key from that source. `/api/v1/ssh/keys` is admin-only.
- **DNS and egress**: the optional smart DNS (`ziroctl dns enable`) only answers loopback and allowed networks. It
  rate-limits clients, verifies DNS-over-TLS certificates and can block domains. Apps deployed with `--egress`
  reach only their allowed domains and CIDRs; see [dns.md](dns.md).
- **Security modules** (opt-in, never preinstalled): `ziroctl module enable security` installs the `clamav`
  antivirus (clamd on a local socket, signature updates, daily scans, `security scan --av`, `av` alerts) and
  `auditd` (a CIS-aligned kernel audit trail), `integrity` (IMA: what the host runs is checked daily against the OS
  image and signed packages; `ziroctl security integrity`), and `clamav-onaccess` (blocks opening infected
  files). See [modules.md](modules.md).
- **Hardening score**: `ziroctl security audit [--json]` scores the host against 30 CIS-mapped checks (kernel and
  network sysctls, SSH, firewall and guard, file permissions, audit chain). Fresh images score 100.
- **Backups**: archives are root-only (0600) and unencrypted, and they contain private keys. Restore rejects
  paths outside the backup allowlist, traversal, hardlinks, and writes through symlinks.
  Creation stages bytes in a private file, publishes the finished archive atomically, and refuses existing
  archive/checksum destinations. Output filesystems must enforce 0600 permissions and support hard links
  (for example ext4); unsupported filesystems fail before archiving secrets. Choose a trusted directory.
- **Clustering**: joins pin the cluster CA (by hash) plus a join token, and each node gets its own token (masters
  store only hashes). Masters hold CA-signed certificates issued from CSRs. Raft (tcp/7444) and master-to-master
  API calls require mutual TLS with those certificates, and workers can never obtain one. ziroctl reaches its
  local cluster-master through a root-only unix socket. Backups leave out the Raft data, the CA key and the
  master key. See [clustering.md](clustering.md).
  A replica is reported running only when its assigned Ready node reports it.
- **Cluster network policy**: new clusters default to `deny`. Mesh traffic reaches an app's port only from nodes
  that run an app listed in its `allow_from` (`ziroctl cluster deploy --allow-from web`). On the pod network
  (default for new clusters) that means from the allowed apps' own replica IPs, including same-node traffic. It
  is enforced in each node's `inet ziro_cluster` nftables table, and the agent does not configure the mesh until that table is in
  place. Check it with `ziroctl cluster policy ls`.
- **Image policy**: `ziroctl cluster policy images` limits apps to allowed registries and can require cosign
  signatures by your keys. Verified images are pinned by digest, so nodes run exactly what was verified. The leader
  re-checks every changed image. See [clustering.md](clustering.md#image-policy).
- **Secrets at rest**: cluster secrets and the CA key are sealed (AES-256-GCM) with a cluster data key in Raft,
  snapshots and files. Each master wraps its copy with a `file`, `tpm` (TPM 2.0, salted and encrypted sessions)
  or `command` (KMS/Vault/HSM) provider. Masters fetch the key from each other only over mutual TLS, and every
  fetch is audited. See [clustering.md](clustering.md#secrets-at-rest).
- **Monitoring and compliance**: `GET /api/v1/metrics` (Prometheus text format; a `viewer` token is enough) reports
  host health, service state and, on masters, node readiness, replica health, control-plane membership and which
  security controls are in force. [compliance.md](compliance.md) maps the controls to NIST SP 800-190, CIS Controls
  v8 and SOC 2, with the command that produces evidence for each and the known gaps.
- **Credential rotation**: node tokens rotate automatically every 30 days, and at once with
  `ziroctl cluster rotate tokens`. The agent generates the new token and sends it over the authenticated channel. The
  previous token stays valid for an hour, and using it triggers another rotation, so a lost reply never locks a node
  out. Master certificates renew 30 days before expiry, and at once with `ziroctl cluster rotate certs`. The cluster
  data key rotates with `ziroctl cluster keys rotate`: it is distributed to every master before the secrets are
  re-sealed, then the old key is dropped and the Raft log compacted. Rotating the cluster CA is not supported yet;
  it is valid for 10 years.
- **Audit log**: every mutating `ziroctl` command run as root, ziro-api service action, and cluster join, leave
  or rejected credential is appended to `/var/log/ziro/audit.log` (0600). Each record holds the SHA-256 of the
  previous one. `ziroctl audit verify` exits non-zero at the first changed or removed record, and
  `ziroctl audit log --since 24h --json` exports records. `KEY=VALUE` values and credential flags are redacted.
  The log rotates by rename at 10 MB and keeps 10 generations. Because root can rewrite the whole chain, forward
  the log off-host or store the head hash printed by `verify` when you need non-repudiation.
- **Kernel & sysctl**: the `custom` kernel flavor (the default) enforces module signing (the persistent Ziro key in releases; unsigned modules are rejected), loads IMA, and zeroes memory on free; see [kernel/README.md](../kernel/README.md#security-defaults). Its config fragments add KASLR, strict RWX, a strong stack protector, hardened
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
  - Nodes sit in private subnets and reach the internet through a NAT gateway. `public_node_ips = true` restores
    public IPs; otherwise reach nodes through a bastion, SSM or a WireGuard peer.
  - The Kubernetes API load balancer is internal unless `api_lb_internal = false`.
  - NodePorts are reachable only from inside the VPC unless you list `nodeport_allowed_cidrs`.
  - Outbound traffic to the internet is limited to HTTPS/HTTP, DNS, NTP and WireGuard; everything else stays
    inside the VPC.

## Security boundary checks

Explicit remote user-data requires HTTPS, including redirects. Installer local files remain supported.
Automatic metadata is cloud-gated, bypasses environment proxies, and refuses redirects. Image tar/cpio
members use root ownership independently of the build user's UID. Quarantine rules precede established
and ICMP accepts; loopback remains trusted and forwarding/NAT policy belongs to container networking.
The iptables fallback temporarily sets INPUT to DROP during replacement and restores the requested
policy only after all rules succeed. A failed replacement reports an error and leaves INPUT closed.

`ziroctl security harden` rewrites managed SSH settings in global and Match scopes, preserves stronger
root-login and retry restrictions, and validates with `sshd -t` before replacement. Active Include
directives cause a visible failure; consolidate included policy before invoking hardening. The audit
uses active directives and does not count comments as enforcement.

Run `make test-unit`, `python3 tests/security/test-userdata-transport.py`, and
`python3 tests/security/test-artifact-metadata.py <rootfs.tar.gz> <initramfs.cpio.gz>` for regressions.
These checks do not establish cloud-image boot correctness, external agent isolation, or absence of all
vulnerabilities. Agents receiving a host runtime socket or privileged mounts receive corresponding host
authority; the cluster agent is a workload reconciler rather than an LLM permission sandbox.

The DHCP CNI binary is rebuilt from pinned upstream source with patched x/net in both shipped locations.
See [the override recipe](../packages/cni-dhcp/README.md), including package upgrade limitations.
`tests/security/test-cni-dhcp.py <rootfs-directory> <x86_64|arm64>` checks its dependencies, static linking,
and CNI VERSION response; it does not exercise a custom DHCP lease lifecycle.
