# Getting Started with Ziro-OS

Welcome to **Ziro-OS**! This guide walks you through using, testing, and building Ziro-OS for container workloads, microVMs, and cloud environments.

---

## 🎯 What is Ziro-OS?

Ziro-OS is an ultra-lightweight, container-native operating system built from scratch to run container workloads with maximum performance, minimal attack surface, and instant boot times.

- **Minimal Base**: ≈16 MB Docker base image (`ziro-os:latest`) and a complete container host OS under 300 MB with `containerd`, `runc`, and CNI plugins.
- **Stateless & Immutable**: Hardened read-only rootfs with minimal writeable paths.
- **C99 PID 1 Supervisor**: Statically linked `ziro-init` providing sub-second boot, cgroups v2 hierarchy, loopback networking, and automated zombie process reaping.
- **Integrated Package Management**: Fast, signed package installation via `ziropkg` and `ziroctl pkg`.
- **Multi-Architecture**: Native support for `x86_64` and `arm64` (Apple Silicon & cloud ARM64).

---

## 🐳 1. Using the Docker Base Image

Ziro-OS provides an Alpine-like minimal container base image built `FROM scratch`.

### Build Locally

```bash
# Build the Docker base image for your current architecture
make docker-image
```

### Run an Interactive Shell

```bash
docker run --rm -it ziro-os:latest sh
```

Inside the container:
```sh
/root # uname -a
Linux 6.x ... aarch64/x86_64
/root # cat /etc/os-release
NAME="Ziro-OS"
ID=ziro-os
/root # ziroctl version
ziroctl version 1.0.0
```

### Use in Your Own Dockerfiles

You can build container images directly on top of `ziro-os:latest`:

```dockerfile
FROM ziro-os:latest

# Install necessary packages with ziropkg
RUN ziropkg install curl ca-certificates

WORKDIR /app
COPY . .

CMD ["/bin/sh"]
```

---

## 📦 2. Managing Packages with `ziropkg`

Ziro-OS includes `ziropkg`, a fast package manager with cryptographic signature verification that lets you install additional utilities (e.g. `curl`, `jq`, `htop`, `git`, `python3`) on demand.

### Basic Commands

```bash
# Install packages (e.g. curl)
ziropkg install curl

# Install multiple packages
ziropkg install jq git htop

# Search the package repository
ziropkg search redis

# Inspect package details
ziropkg info curl

# List installed packages
ziropkg list

# Remove a package
ziropkg remove curl

# Update repository indexes
ziropkg update
```

### Integration with `ziroctl`

Package management is also integrated directly into the `ziroctl` unified CLI:

```bash
# Install via ziroctl
ziroctl pkg install curl jq

# List installed packages
ziroctl pkg list

# Search packages
ziroctl pkg search nginx
```

---

## 🔍 3. System Inspection & Security Audit

The `ziroctl` CLI provides built-in system inspection and security auditing out of the box:

```bash
# Inspect host/container system metrics, memory, kernel, and mounts
ziroctl system inspect

# Run a CIS-style security audit (verifies immutable mounts, ASLR, sysctl hardening)
ziroctl security audit

# Output in JSON format for automated CI/CD pipelines
ziroctl system inspect --json
ziroctl security audit --json
```

---

## 🖥️ 4. Running Ziro-OS in a MicroVM (QEMU)

Experience Ziro-OS booting as a standalone operating system with `containerd` and CNI plugins:

### Prerequisites
- macOS: `qemu-system-aarch64` or `qemu-system-x86_64` (uses Apple Silicon HVF acceleration)
- Linux: `qemu-system-x86_64` or `qemu-system-aarch64` (uses KVM acceleration)

### Launch MicroVM

```bash
# Automatically boots Linux kernel with full Ziro-OS initramfs in QEMU
make run-qemu
```

Upon boot, `ziro-init` initializes the cgroup v2 hierarchy, loopback networking, starts `containerd`, and drops you into an interactive console:

```text
==================================================
  🌀 Ziro-OS Container System (arm64 / x86_64)
  Init: ziro-init v1.0.0 (C99 Supervisor)
==================================================
[ziro-os]# ziroctl system status
[ziro-os]# ziroctl security audit
```

*(To exit QEMU: press `Ctrl+A`, then press `X`)*

---

## 💿 5. Generating Bootable Hybrid ISO

You can generate a bootable hybrid ISO image compatible with UEFI and Legacy BIOS for deployment in VMware, Proxmox, VirtualBox, or bare-metal servers:

```bash
make image-iso
```

Output ISO image:
```text
build/ziro-os-<arch>.iso
```

---

## 🏗️ 6. Building from Source & Multi-Arch

Ziro-OS supports deterministic cross-compilation across architectures:

```bash
# Build all components for current host architecture
make all

# Cross-compile CLI tools for x86_64 and arm64
make tools-all

# Build rootfs archives for both architectures
make rootfs-all

# Build multi-architecture Docker image using Docker buildx
make docker-multiarch

# Run the full test suite
make test
```

---

## 🤝 Next Steps

- Check out [Contributing Guide](../CONTRIBUTING.md) to learn how to contribute code, fix issues, and improve modules.
- Read [AGENTS.md](../../AGENTS.md) for architectural guidelines and development principles.
- Join the community discussions and report issues on GitHub!