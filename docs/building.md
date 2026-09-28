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

### QEMU boot test

`make test-boot` boots `build/vmlinuz-<arch>` with its initramfs in QEMU. It then drives the serial console and
checks that:

- the kernel matches the shipped modules
- `nf_tables`, `wireguard` and `overlay` load
- containerd starts
- Sentinel and the `inet ziro` firewall are active from boot
- DHCP works
- a real `nerdctl run` succeeds

It needs `qemu-system-x86_64` or `qemu-system-aarch64` and uses KVM (Linux) or HVF (macOS) when available.
Pass `--no-pull` to the script if the machine has no internet access. The serial log is written to
`build/qemu-boot-<arch>.log`. CI runs this test on every PR.

## 🐧 Kernel & Modules

The kernel and its modules always come from **one** source, so their versions always match:

| Mode | Kernel | Modules |
|---|---|---|
| default | Alpine `linux-virt` (installed by `packages/build-rootfs.sh`) | the same `linux-virt` package |
| `BUILD_FROM_SOURCE=1` | `kernel/build-kernel.sh` using `kernel/configs/config-<arch>` | built by the same kernel build (`modules_install`) |

For a source build, export the variable for the **whole** build:
`BUILD_FROM_SOURCE=1 make image-iso TARGET_ARCH=x86_64`.

`build/kernel-release-<arch>` records the kernel version. `images/iso/build-iso.sh` refuses to build an ISO when
that version has no matching `lib/modules/<version>` in the rootfs. All build containers use the pinned
`ALPINE_IMAGE` (default `alpine:3.24`); override it to move to a newer Alpine release.
