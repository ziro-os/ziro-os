# Technical Design & Architecture (Technology Stack) — Ziro‑OS

This file outlines key technical decisions, system architecture, and interfaces for Ziro‑OS.

---

## 🧩 Architecture Overview

Ziro‑OS operates as a minimal host layer whose sole purpose is to run container workloads. The architecture consists of:

1. **Kernel Layer**

   - Minimal Linux kernel (or microkernel if chosen)
   - Essential drivers (network, storage, virtualization)
   - Built-in support for container features: namespaces, cgroups, seccomp, capabilities

2. **Userland / Init Layer**

   - `init` (or minimal init system) to bootstrap services
   - BusyBox or equivalent for shell, file tools, networking tools
   - Musl libc or another lightweight libc

3. **Container Runtime Layer**

   - **containerd** as the core runtime daemon
   - An OCI runtime (e.g. runc or crun)
   - Docker Engine / Podman integration modules (socket translation, CLI wrapper)

4. **Module Layer / Plugins**

   - CNI plugin framework for networking
   - Storage / volume driver modules
   - Logging / metrics / telemetry modules
   - Security modules (seccomp rules, AppArmor, SELinux optional)

5. **Control & Tooling**
   - `ziroctl` CLI to interact with system, containers, modules
   - APIs or socket interfaces for orchestration tools

---

## 🔧 Key Technical Decisions

### 🧠 Base libc & Toolchain

- **musl libc** is preferred for reduced size, static linking, and simplicity
- Cross‑compilation toolchains (e.g. `cross` or `buildroot` style) will be used
- Use of **BusyBox**-style multi‑call binaries for core utilities

### 🏗 Container Runtime & Compatibility

- Use **containerd** as the core runtime; it handles pulling, snapshotting, lifecycle
- Use **runc**, **crun**, or similar for low-level runtime
- For Docker compatibility, wrap or proxy Docker API calls to containerd
- For Podman, ensure CLI compatibility or translation layer

### 🔌 Modularity & Plugins

- Each plugin or module should define an interface (e.g. JSON/YAML manifest)
- Plugins should be compiled or packaged in isolation
- Dynamic loading (shared libraries) discouraged for core; optional modules may be loaded

### 🌐 Networking (CNI)

- Support standard CNI plugins (bridge, macvlan, flannel, calico)
- The OS should host a simple CNI plugin loader or controller
- Support dynamic network interface configuration

### 📂 Storage & Volumes

- Support overlayfs, ext4, xfs as base FS options
- Volume modules (block, filesystem, network storage) based on drivers
- Snapshot / snapshotter plugins via containerd’s interface

### 🔒 Security & Hardening

- Minimal service exposure
- Enable seccomp filters by default
- Optionally include AppArmor or SELinux (user choice)
- Immutable root filesystem; writeable areas only under controlled dirs (e.g. `/var/lib/containers`)

### 🧪 Testing & Validation

- QEMU-based boot & basic function tests
- Container CRUD tests: pull, run, stop, delete
- Networking tests (CNI reachability)
- Storage tests (volume mount, read/write)
- Regression suite under CI

---

## 🔄 Upgrade & Update Strategies

- **Immutable topology**: updates apply by swapping full images or modules
- **Atomic module replacement**: module updates should be transactional
- **Rollback support**: maintain snapshots of prior image or module versions
- **Declarative config**: `ziroctl apply config.yaml` style operations

---

## 🔍 Interfaces & APIs

- **ziroctl**: primary CLI — manage modules, containers, configs, status
  - `ziroctl module install <name>`
  - `ziroctl module remove <name>`
  - `ziroctl container run …` (wraps container CLI)
  - `ziroctl config apply …`
- **REST / gRPC API (optional future)**: for programmatic orchestration
- **Socket / Unix API**: for internal tooling and orchestration tools
