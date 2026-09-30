# Compliance mapping

This page maps Ziro-OS controls to common frameworks, and gives the command that produces evidence for each. It is
a starting point for an assessment, not a certification: a control is only effective once it is configured and
operated. Your organization owns the policies, reviews and processes around it (shared responsibility).

Frameworks: **NIST SP 800-190** (Application Container Security Guide), **CIS Controls v8**, and the **SOC 2**
Trust Services Criteria (2017, revised points of focus).

## Evidence commands

| Evidence | Command (on a master unless noted) |
|---|---|
| Audit trail is intact | `ziroctl audit verify` (every host) and `ziroctl audit log --since 720h --json` |
| Network segmentation in force | `ziroctl cluster policy ls --json` |
| Image provenance policy | `ziroctl cluster policy images --json` |
| Secrets encrypted at rest; key custody | `ziroctl cluster keys status --json` (each master) |
| Control-plane redundancy | `ziroctl cluster members --json` |
| API access inventory | `ziroctl api token ls --json` |
| Credential age (rotation) | `ziroctl cluster nodes --json` (`token_issued`), metric `ziro_cluster_node_token_age_seconds` |
| Continuous monitoring | `GET /api/v1/metrics` (Prometheus; a `viewer` token is enough) |
| Host hardening | `ziroctl security audit --json` (every host; CIS Linux Benchmark sections per check) |
| Intrusion prevention state | `ziroctl security protect status --json`, `ziroctl security bans list --json` |
| Alert routing | `ziroctl security alerting list --json` |

## NIST SP 800-190

| Risk area (section) | Ziro-OS control |
|---|---|
| Image vulnerabilities and configuration defects (4.1.1–4.1.2) | Minimal base image (musl, BusyBox); `govulncheck` gate in CI for every Go component |
| Untrusted images (4.1.5) | Registry allowlist and cosign signature verification, with apps pinned to the verified digest (`cluster policy images`) |
| Insecure registry connections (4.2.1) | HTTPS registries only (the token realm must be HTTPS); pulls by digest |
| Unbounded administrative access (4.3.1) | Scoped API tokens (`viewer`/`operator`/`admin`) with expiry; CLI through a root-only socket |
| Unauthorized access (4.3.2) | Joins pin the cluster CA plus an expiring join token; per-node tokens (hashed, rotated); masters authenticate with mutual TLS |
| Poorly separated inter-container traffic (4.3.3) | Default-deny app network policy (`allow_from`), enforced per container IP on the pod network, including same-node traffic |
| Orchestrator node trust (4.3.5) | Only CA-signed master certificates can join Raft; workers can never obtain one; audited data-key fetches |
| Runtime and app vulnerabilities (4.4) | Containers run with no-new-privileges and without NET_RAW by default; containerd/runc seccomp defaults; host firewall default-deny; secrets never in argv or env listings of other apps (0600 env files on tmpfs) |
| Large host attack surface (4.5.1) | Minimal OS; `custom` kernel with module signing, lockdown and KASLR; hardened sysctls; login required on consoles |
| Improper user access rights (4.5.4) | SSH hardening (`security harden`); console root shell only via the explicit recovery entry |
| Host file system tampering (4.5.5) | File integrity baseline (Sentinel); immutable root filesystem is on the roadmap (not yet enforced) |

## CIS Controls v8 (selected safeguards)

| Safeguard | Ziro-OS control |
|---|---|
| 3.10 Encrypt sensitive data in transit | TLS 1.2+ everywhere; WireGuard mesh between nodes; mutual TLS between masters |
| 3.11 Encrypt sensitive data at rest | Secrets and the CA key sealed with AES-256-GCM; data key wrapped per master (`file`, `tpm`, `command`/KMS); `cluster keys rotate` |
| 4.1/4.2 Secure configuration of assets | Hardened defaults (firewall default-deny, API on loopback, deny-by-default mesh policy for new clusters) |
| 4.7 Manage default accounts | No default passwords; login required on installed systems |
| 5.2/6.x Access control and credential management | Unique scoped tokens; expiry; revocation; automatic rotation of node tokens (30 days) and master certificates |
| 8.2/8.5/8.9 Audit log management | Tamper-evident, hash-chained audit log on every host; forward it to a central collector (8.9) |
| 12.2/13.4 Network segmentation and traffic filtering | App policy on the mesh; gateway CIDR allowlists and per-client rate limits |
| 13.1/8.11 Monitoring and alerting | Prometheus metrics (node readiness, replica health, control-plane membership, security-control state); signed webhook alerts for threats, integrity changes and bans |
| 13.3/13.8 Network intrusion prevention | Ziro Guard: per-source SYN/connection/ICMP limits, kernel port-scan bans, SSH brute-force bans with escalation |
| 16.1/16.4 Secure software supply chain | Signed-image policy; pinned dependencies; `govulncheck` and SAST/dependency scanning in CI |

## SOC 2 (Trust Services Criteria)

| Criterion | Ziro-OS control |
|---|---|
| CC6.1 Logical access; encryption keys | RBAC API tokens; mutual TLS control plane; data-key custody through the key providers; data-key rotation |
| CC6.2/CC6.3 Provisioning and removal | `api token create/revoke`; `cluster member rm` and `node rm` revoke credentials immediately |
| CC6.6 Boundary protection | Host firewall; mesh policy; gateway allowlists, rate limits and TLS |
| CC6.7 Transmission of data | TLS, WireGuard, mutual TLS |
| CC6.8 Prevent unauthorized or malicious software | Registry allowlist and signature verification with digest pinning |
| CC7.1 Configuration management | Declarative `cluster apply`; every spec change is a new revision |
| CC7.2 Monitoring for anomalies | Metrics endpoint; audit log; Sentinel detections pushed as signed webhook alerts |
| CC7.3/CC7.4 Incident response | Automatic bans of brute-force and scanning sources; alerts with host, node and cluster context |
| CC8.1 Change management | Every administrative change is audited (who, what, result) and can be rolled back (`cluster rollback`) |
| A1.2 Availability / recovery | 3- or 5-master Raft control plane with automatic failover; workloads keep running if the control plane is down; backups |

## Known gaps

These are open, so plan compensating controls:

- **Identity:** there is no SSO/OIDC for the admin API. Tokens are per integration, not per person. CLI actions
  are attributed to the local user (uid, `sudo` user, SSH source address).
- **Audit log:** it is per host and root can rewrite it entirely. Forward it off-host (SIEM) and record
  `audit verify` head hashes externally.
- **PKI:** rotating the cluster CA is not supported yet (the CA is valid for 10 years). Master certificates and
  node tokens do rotate.
- **Signatures:** keyless (Fulcio/Rekor) signatures and cosign's OCI-referrers bundle format are not verified.
- **Backups:** they are not encrypted. They leave out keys and secrets unless you pass `--include-secrets`.
- **Cryptography:** Go's standard library is used. Where FIPS 140-3 is required, build with Go's FIPS mode
  (`GOFIPS140`) and validate that build separately.
- **Root filesystem:** an immutable, verified root filesystem is on the roadmap. Today, file integrity monitoring
  (Sentinel) detects changes.
