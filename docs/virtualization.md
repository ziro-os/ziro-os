# Ziro-OS Virtualization & Cloud Hypervisor Guide

Ziro-OS is engineered for cloud-native virtualization technologies, providing sub-second boot times, minimal memory consumption, and VirtIO acceleration.

---

## 🏎️ Supported Hypervisors

### 1. QEMU / KVM
The primary development and production hypervisor.
- **Direct Kernel Boot**: Launches instantly using `-kernel vmlinuz` and `-initrd initramfs.cpio.gz` without traditional bootloader latency.
- **Hardware Acceleration**:
  - macOS: Apple Hypervisor Framework (`-accel hvf`)
  - Linux: Kernel-based Virtual Machine (`-enable-kvm`)

Launch with:
```bash
make run-qemu
```

### 2. MicroVMs (AWS Firecracker & Cloud-Hypervisor)
Ziro-OS's direct kernel + initramfs architecture is designed for microVM hypervisors:
- Sub-100ms boot time from cold start.
- Memory overhead < 64MB RAM.
- VirtIO-MMIO and VirtIO-PCI block and network interfaces enabled by default.

### 3. VMware / VirtualBox / Proxmox VE
Deploy Ziro-OS as an ISO virtual appliance:
1. Generate the hybrid ISO:
   ```bash
   make image-iso
   ```
2. Attach `build/ziro-os-<arch>.iso` to the virtual machine CD-ROM drive.
3. Boot with UEFI or legacy BIOS support enabled.
