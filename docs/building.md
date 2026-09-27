# Building Ziro-OS (Multi-Architecture)

Ziro-OS features a fully reproducible, Docker-isolated multi-architecture build system supporting both `x86_64` (Intel/AMD) and `arm64` (Apple Silicon & ARM servers).

---

## 🏗️ Target Architectures

- `x86_64` (amd64): For Intel/AMD cloud VMs, workstations, and bare metal servers.
- `arm64` (aarch64): For Apple Silicon machines, AWS Graviton, and ARM-based cloud instances.

---

## 🛠️ Build Commands

### Default Build (Current Host Architecture)
```bash
make all
```
Compiles:
1. `bin/ziroctl`: Statically compiled Go CLI.
2. `build/ziro-rootfs-<arch>.tar.gz`: Minimal container base (< 10MB).
3. `build/ziro-initramfs-<arch>.cpio.gz`: Full container OS initramfs.
4. `ziro-os:latest`: Local Docker container image.

### Building for a Specific Architecture

#### Build for x86_64
```bash
make all TARGET_ARCH=x86_64
```

#### Build for ARM64
```bash
make all TARGET_ARCH=arm64
```

### Multi-Architecture Artifacts

```bash
# Build CLI tools for all platforms
make tools-all

# Build Rootfs archives for all platforms
make rootfs-all

# Build multi-arch Docker image with buildx (linux/amd64 & linux/arm64)
make docker-multiarch
```

---

## 🧪 Verification & Testing

```bash
# Run unit tests and container smoke tests
make test
```
