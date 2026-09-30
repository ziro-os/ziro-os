# AGENTS.md

## Project Overview

- **Name**: Ziro‑OS
- **Purpose**: A cloud‑native, ultra‑lightweight OS built from scratch to host container workloads. Minimal base, fast boot, small footprint, with first‑class support for containerd, Docker/Podman, and OCI runtimes.
- **Design philosophy**: Minimal by design. Born for the cloud.

---

## Setup & Build

1. **Kernel**

   - Obtain or patch the Linux kernel (or microkernel) with only essential drivers (networking, storage, virtualization).
   - Configure for fast boot, namespaces, cgroups, seccomp support.

2. **Userland**

   - Use musl libc.
   - BusyBox‑style utilities for core tools (shell, file utilities, networking tools).

3. **Container Runtime Layer**

   - Include `containerd` as the core runtime.
   - Provide or integrate OCI runtime(s) like `runc` or `crun`.
   - Add wrappers or shims for Docker Engine / Podman CLI compatibility if needed.

4. **Module & Plugin Support**

   - Networking (CNI plugins).
   - Storage / volume drivers.
   - Logging / telemetry modules.
   - Security modules (seccomp, optional AppArmor/SELinux).

5. **Image Building**

   - Scripts to build bootable images (VM, cloud, bare metal).
   - Build rootfs + kernel bundles.

6. **CLI / Tooling**
   - `ziroctl` (or equivalent) to manage modules, containers, config, images.

---

## Core Goals & Constraints

- **Minimal Base**: every bootable host image (ISO and initramfs, for both kernel flavors) must stay **< 300 MB** (enforced in CI); the minimal container base rootfs is ≈16 MB.
- **Stateless & Immutable by default**: aim for immutable root filesystem, minimal writeable areas.
- **Cloud‑Native First**: containerd, Docker/Podman support out of the box.
- **Modular Extensible Architecture**: allow plug‑in modules.
- **Security Hardened**: use least privileges, seccomp, capability restrictions; optional AppArmor/SELinux.

---

## Commands Agents Should Know

- Build kernel: e.g. `make` / `make defconfig && make` in `kernel/`
- Build userland: compile musl + BusyBox + essential tools
- Install container runtime: build or integrate containerd + runtime
- Build images: via scripts in `images/` for different targets (VM, cloud, bare metal)
- Run tests: basic smoke tests (e.g. boot image, start container, run container, network ping, storage mount)
- Manage modules: via `ziroctl module install/remove/enable/disable`

---

## Code Style & Conventions

- Prefer static linking where possible (for minimal dependencies).
- Keep dependencies minimal. No large frameworks unless absolutely needed.
- Single responsibility per module.
- Clear versioning of packages/modules.
- Configuration via declarative manifest (YAML/JSON) where applicable.

---

## Testing & CI

- Smoke tests for:

  - Booting images (e.g. via QEMU)
  - Container runtime functionality (pull, run, stop)
  - Networking (CNI) tests
  - Storage / volume mount read/write

- Automated builds for images + modules.
- Linting / style enforcement (shell scripts, configs).
- Security checks: check for unnecessary services, privilege escalations.

---

## PR / Contribution Guidelines

- Before submitting a PR, run full build + test suite.
- Include any new module’s manifest/recipe with metadata (name, version, dependencies).
- Ensure configuration / defaults don’t introduce breakage.
- Follow versioning schema for modules / packages.
- Document new features or changes in `docs/`, especially `docs/architecture.md` for technical decisions.

---

## Security & Deployment Notes

- Root filesystem should be immutable; writeable paths minimized.
- Use of seccomp filters by default.
- Optional support for MAC systems (AppArmor or SELinux) as opt‑in.
- For cloud images, ensure cloud provider security best practices (user accounts, SSH keys, etc.).
- Avoid embedding secrets; use environment / runtime injected secrets only.

---

## Stretch & Future Features

- Boot support for AWS / GCP / Azure VMs.
- Integrate observability: Prometheus / OpenTelemetry modules.
- `ziroctl` enhancements: config management, rollback, atomic updates.
- Package manager (ZiroPkg) for minimal module/package installation.

---

## Agent‑Specific Notes

- If the agent is asked to generate files, scaffold under the defined structure: `kernel/`, `rootfs/`, `packages/`, `images/`, `tools/`, `docs/`.
- Agent should reference technical decisions in `docs/architecture.md` when generating code or architecture.
- When in doubt, aim for minimalism and clarity.

---

> _Ziro‑OS — built for containers. built for speed. built for clarity._
