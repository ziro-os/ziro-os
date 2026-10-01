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
2. `build/ziro-rootfs-<arch>.tar.gz`: Minimal container base (≈16 MB).
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

### Building on macOS

The rootfs is assembled through a Docker bind mount. On the default case-insensitive APFS volume,
files that differ only in case collide: iptables' `libxt_MARK.so` and `libxt_mark.so`, for example.
The image would lose those extensions, and container port publishing would break. The build refuses
to run in that case, so build from a case-sensitive volume:

```sh
hdiutil create -size 40g -fs 'Case-sensitive APFS' -volname ziro -type SPARSE ~/ziro.sparseimage
hdiutil attach ~/ziro.sparseimage
git worktree add /Volumes/ziro/ziro-os && cd /Volumes/ziro/ziro-os && make rootfs TARGET_ARCH=arm64
```

Rebuilds are fast: `build/apk-cache` keeps packages, and the custom kernel is only rebuilt when
`kernel/**` changes (ccache makes a config change a ~10 minute rebuild).

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

## 🐧 Kernel Flavors

Ziro-OS ships two kernel flavors. Each one produces its own, separately named artifacts. **`custom`, the hardened
Ziro kernel, is the default** for builds and new installs. `alpine` is the fallback.

| | `alpine` | `custom` (default) |
|---|---|---|
| Kernel | Alpine `linux-virt` LTS package | Ziro kernel built from kernel.org LTS sources (`KERNEL_VERSION`, default 6.18.54) |
| Config | Alpine's (tuned for VMs) | upstream arch `defconfig` (broad hardware) + `kernel/configs/ziro-common.config` + `ziro-<arch>.config` |
| Targets | KVM/QEMU, Proxmox, most cloud VMs | bare metal plus KVM, Xen, Hyper-V/Azure, VMware, AWS Nitro (ENA/NVMe), GCP (gVNIC); boot-critical drivers built in |
| Hardening | Alpine defaults | See [kernel/README.md](../kernel/README.md#security-defaults): lockdown, Yama + Landlock + IMA + BPF LSMs, init-on-alloc/free, page-table checks, KFENCE, no kexec/hibernation/SysRq, **enforced module signing** (persistent Ziro key in releases) |
| Performance | Alpine defaults | BBR + fq by default, MPTCP, kTLS, nftables flowtables, THP on madvise, zswap |
| Artifacts | `vmlinuz-<arch>`, `ziro-initramfs-<arch>.cpio.gz`, `ziro-os-<arch>.iso` | same names with a `-custom` suffix, plus `kernel-config-<arch>-custom` |

```bash
make rootfs image-iso TARGET_ARCH=x86_64                       # custom flavor (builds the kernel when kernel/ changed)
make rootfs image-iso TARGET_ARCH=x86_64 KERNEL_FLAVOR=alpine  # alpine flavor
make test-boot TARGET_ARCH=x86_64                              # boot-test (KERNEL_FLAVOR picks the flavor)
CONFIG_ONLY=1 ./kernel/build-kernel.sh arm64                   # check config fragments in a minute, no compile
```

The custom build fails if `olddefconfig` drops or changes any option from the Ziro fragments, so a renamed or
unsatisfiable symbol can never ship silently. CI (`.github/workflows/kernel-custom.yml`) builds and boot-tests
the custom flavor natively on x86_64 and arm64, and `ci.yml` builds and boot-tests the alpine flavor. Releases
publish both flavors. Hosts keep upgrading within their flavor; `ziroctl upgrade --flavor custom` moves an
alpine host to the hardened kernel (rollback restores the previous one).

The kernel and its modules always come from **one** source. `build/kernel-release-<arch>[-custom]` records the
version, and `images/iso/build-iso.sh` refuses to build an ISO whose kernel has no matching `lib/modules/<version>`
in the rootfs. All build containers use the pinned `ALPINE_IMAGE` (default `alpine:3.24`).

## 📏 Image Size Goal

Every bootable host image (ISO and initramfs, both flavors) must stay **under 300 MB** (decimal MB). CI and the
release workflow fail if an artifact crosses that limit. The minimal container base rootfs is about 16 MB.
The release page reads real artifact sizes from the GitHub Releases API instead of hardcoding them.
