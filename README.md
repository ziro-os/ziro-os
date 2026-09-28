# 🌀 Ziro-OS

> **Minimal by design. Born for the cloud.**

Ziro-OS is an ultra-lightweight, container-native operating system built from first principles for cloud-native infrastructure, microVMs, and edge computing. Inspired by Alpine Linux's minimalism and modern OCI container runtimes, Ziro-OS provides a secure, minimal, sub-second boot environment purpose-built to run containers without general-purpose OS bloat.

---

## ✨ Key Capabilities

- **Tiny Base Footprint**: ≈16 MB minimal Docker base image (`ziro-os:latest`), built `FROM scratch` with musl libc, BusyBox, `ziroctl`, and `ziropkg`.
- **Integrated Package Manager (`ziropkg`)**: Fast, verified package management out of the box (`ziropkg install curl`, `ziroctl pkg install jq`).
- **First-Class OCI Support**: Native integration with `containerd`, `runc`, and CNI plugins (`bridge`, `loopback`, `portmap`, `firewall`).
- **High-Performance C99 Init (`ziro-init`)**: Robust PID 1 supervisor managing early mounts, cgroups v2 hierarchy, loopback networking, containerd lifecycle, and non-blocking zombie process reaping.
- **True Multi-Architecture**: Full support for `x86_64` (Intel/AMD) and `arm64` (Apple Silicon & ARM servers).
- **Two Kernel Flavors**: Alpine `linux-virt` (default, VM-tuned) or the Ziro custom LTS kernel (bare metal plus KVM, Xen, Hyper-V/Azure, VMware, AWS Nitro and GCP, with enforced module signing). Each flavor ships its own images, and CI boot-tests every build in QEMU.
- **Sub-Second Virtualization**: Direct-kernel boot for QEMU microVMs, AWS Firecracker, and Cloud-Hypervisor, alongside hybrid UEFI/BIOS bootable ISO generation.
- **Built-in Security & Hardening**: Immutable root filesystem, Linux namespaces, kernel seccomp filters, and hardened sysctl parameters.

---

## 🚀 Quick Start

### 1. Docker Base Image & Package Management

Build and run the official Ziro-OS base container image locally:

```bash
# Build the Docker image
make docker-image

# Run an interactive shell
docker run --rm -it ziro-os:latest sh

# Check version
docker run --rm ziro-os:latest ziroctl version

# Install additional packages inside the container (e.g. curl)
docker run --rm ziro-os:latest /bin/sh -c "ziropkg install curl && curl --version"
```

Use directly in your Dockerfiles:
```dockerfile
FROM ziro-os:latest

RUN ziropkg install curl ca-certificates

WORKDIR /app
CMD ["ziroctl", "system", "inspect"]
```

---

### 2. Boot in QEMU (MicroVM)

Launch a direct-kernel microVM with hardware acceleration (Apple Silicon HVF on macOS, KVM on Linux):

```bash
# Launch microVM with containerd and interactive shell
make run-qemu
```

Inside the booted VM:
```bash
ziroctl system status
ziroctl security audit
```

*(Press `Ctrl+A`, then `X` to exit QEMU)*

---

### 3. Bootable Hybrid ISO & Proxmox / Bare Metal Installation

Generate a true hybrid bootable ISO for VMware, VirtualBox, Proxmox VE (both SeaBIOS and OVMF UEFI), or physical bare metal:

```bash
make image-iso
```
Output artifact: `build/ziro-os-<arch>.iso`

#### Proxmox VE & Hypervisor Deployment
1. Upload `ziro-os-x86_64.iso` to Proxmox VE ISO storage (or your hypervisor of choice).
2. Create a VM with standard settings (**SeaBIOS** or **OVMF UEFI**, VirtIO / SCSI / SATA / NVMe disk, 512MB+ RAM).
3. Boot the VM. The live container OS discovers all storage drives and loads in under 2 seconds.
4. Launch the interactive TUI installer (with automatic storage discovery and network setup wizard):
   ```bash
   ziro-install
   # or: ziroctl install
   ```
5. Or deploy automatically with zero prompts (cloud-native key authentication, network settings, and user-data script):
   ```bash
   # Automated with DHCP:
   ziro-install -d /dev/sda -n ziro-node-01 -k "ssh-ed25519 AAAA..." -y

   # Automated with Static IP (Rocky/RHEL style):
   ziro-install -d /dev/vda -n ziro-node-01 --ip 192.168.1.50/24 --gateway 192.168.1.1 --dns "1.1.1.1 8.8.8.8" -y
   ```
6. Disconnect the ISO and reboot into your lightning-fast, hardened container host.

---

### 4. Cloud-Native Operations & Diagnostic Utilities (`ziroctl`)

`ziroctl` includes essential toolsets for cloud and systems engineers:

```bash
# System & Cloud Health Diagnostics
ziroctl doctor                         # Run full diagnostic suite (cgroups, containerd, storage, network)
ziroctl cloud inspect                  # Detect hypervisor (Proxmox/AWS/GCP/Azure/Bare Metal) & DMI metadata

# Network Management (Auto DHCP & Static IP Wizard)
ziroctl network status                 # Detailed interface status, MAC, routes, DNS, and connectivity check
ziroctl network setup                  # Interactive Rocky/RHEL-style network configuration wizard
ziroctl network setup -i eth0 --mode dhcp --apply           # Fast auto-DHCP configuration
ziroctl network setup -i eth0 --mode static --ip 10.0.0.50/24 --gateway 10.0.0.1 --dns 1.1.1.1 --apply

# Storage & Partition Management
ziroctl disk list                      # Inspect block devices (VirtIO, SCSI, SATA, NVMe), models, and sizes
ziroctl disk usage                     # Filesystem disk capacity and inode utilization

# Security Hardening & Audits
ziroctl security audit                 # Audit kernel namespaces, seccomp, cgroups v2, and sticky bits
ziroctl security harden                # Apply hardened kernel sysctls, SSH key-only auth, and file permissions
```

---

## 🛠️ Build Commands

| Target | Description |
|---|---|
| `make all` | Build `ziroctl`, `ziropkg`, rootfs, and Docker base image for host architecture |
| `make tools` | Compile static `ziroctl` and `ziropkg` binaries into `bin/` |
| `make tools-all` | Compile `ziroctl` and `ziropkg` for both `x86_64` and `arm64` |
| `make rootfs` | Build minimal rootfs (≈16 MB) and full host initramfs (< 300 MB) |
| `make rootfs-all` | Build rootfs archives for both `x86_64` and `arm64` |
| `make docker-image` | Build local `ziro-os:latest` Docker base image |
| `make docker-multiarch` | Build multi-arch OCI image with Docker buildx (`amd64` + `arm64`) |
| `make image-iso` | Generate bootable hybrid UEFI/BIOS ISO |
| `make run-qemu` | Launch local microVM in QEMU |
| `make test` | Run complete unit tests and container smoke test suite |
| `make clean` | Clean transient build artifacts in `build/` |

---

## 🧬 Project Structure

```
ziro-os/
├── Makefile                       # Top-level build orchestrator
├── README.md                      # Project overview and quick start
├── AGENTS.md                      # Architecture guidelines and conventions
├── .gitignore                     # Prevents binary contamination
│
├── init/                          # Ziro Container OS PID 1 Supervisor
│   ├── ziro-init.c                # C99 PID 1 supervisor (cgroups v2, containerd)
│   └── Makefile                   # Static multi-arch compilation
│
├── rootfs/                        # Clean rootfs skeleton (tracked configs)
│   ├── etc/
│   │   ├── inittab                # Standard process table
│   │   ├── fstab                  # Filesystem mount specifications
│   │   ├── os-release             # Linux identification metadata
│   │   ├── sysctl.d/99-ziro.conf  # Kernel and networking optimizations
│   │   ├── containerd/config.toml # Production containerd configuration
│   │   └── cni/net.d/             # CNI bridge and loopback definitions
│   └── README.md
│
├── packages/                      # Rootfs package assembly engine
│   ├── build-rootfs.sh            # Deterministic multi-arch rootfs builder
│   └── README.md
│
├── images/                        # Target image generation
│   ├── docker/                    # Multi-arch "FROM scratch" Docker image
│   ├── qemu/                      # Universal cross-platform QEMU runner
│   └── iso/                       # Bootable hybrid ISO generator
│
├── tools/                         # Static CLI tooling (Go + Cobra)
│   ├── ziroctl/                   # System & container control CLI
│   └── ziropkg/                   # Package management CLI
│
├── community/                     # Community guides and contributions
│   ├── CONTRIBUTING.md            # Guidelines for contributors
│   └── docs/getting-started.md    # Quickstart guide
│
├── docs/                          # Authoritative documentation
│   ├── architecture.md            # System design and PID 1 supervisor
│   ├── getting-started.md         # Getting started guide
│   ├── building.md                # Multi-arch build documentation
│   ├── security.md                # Security and hardening model
│   └── virtualization.md          # Hypervisor deployment guide
│
└── tests/                         # Automated test suites
    ├── smoke/                     # Docker base image tests
    └── security/                  # Security and configuration audit tests
```

---

## 📚 Documentation & Community

- [Getting Started Guide](community/docs/getting-started.md)
- [Contributing Guidelines](community/CONTRIBUTING.md)
- [System Architecture](docs/architecture.md)
- [Multi-Architecture Building](docs/building.md)
- [Security & Hardening Model](docs/security.md)
- [Upgrading Ziro-OS](docs/upgrade.md)
- [Virtualization & Hypervisors](docs/virtualization.md)

---

## 📜 License

MIT License. Copyright (c) 2026 Sambo Chea and Ziro-OS Contributors.
