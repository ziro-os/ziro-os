# Getting Started with Ziro-OS

This guide covers building, running, and deploying Ziro-OS using Docker, QEMU microVMs, or bootable ISOs.

---

## 🚀 Quick Start (Docker Base Image)

Ziro-OS provides an authentic minimal container base image built `FROM scratch` (similar to Alpine Linux) weighing about 16 MB.

### 1. Build the Docker Image
```bash
make docker-image
```

### 2. Run an Interactive Shell
```bash
docker run --rm -it ziro-os:latest sh
```

### 3. Check System Info with `ziroctl`
```bash
docker run --rm ziro-os:latest ziroctl version
```

### 4. Use in Your Dockerfiles
```dockerfile
FROM ziro-os:latest

WORKDIR /app
COPY . .

CMD ["ziroctl", "system", "status"]
```

---

## ⚡ Running in QEMU (Sub-Second MicroVM Boot)

Ziro-OS can be booted as a direct-kernel microVM with hardware acceleration.

### Prerequisites
- **macOS**: `brew install qemu`
- **Linux**: `sudo apt-get install qemu-system`

### Boot the MicroVM
```bash
make run-qemu
```
- On **macOS Apple Silicon**: Boots with native Hypervisor.framework (`-accel hvf`).
- On **Linux**: Boots with native KVM (`-enable-kvm`).

Once booted, you are greeted with the Ziro-OS PID 1 console where `containerd` is running:
```bash
ziroctl motd
ziroctl security audit
```

To exit QEMU, press `Ctrl+A`, then press `X`.

---

## 💿 Bootable Hybrid ISO (Physical & Hypervisor Installation)

Generate a bootable ISO usable in VMware, VirtualBox, Proxmox, or bare metal:

```bash
make image-iso
```
The resulting hybrid ISO is located at:
`build/ziro-os-<arch>.iso`
