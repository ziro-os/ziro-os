# Ziro-OS Installation Guide

This guide covers building and installing Ziro-OS on various platforms.

## 🛠️ Prerequisites

### Build Dependencies

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    bc \
    bison \
    flex \
    libssl-dev \
    libelf-dev \
    qemu-system-x86 \
    qemu-utils \
    genisoimage \
    grub-pc-bin \
    grub-common \
    cpio \
    gzip \
    parted \
    curl \
    wget \
    git \
    golang-go
```

#### Fedora/RHEL
```bash
sudo dnf install -y \
    gcc \
    make \
    bc \
    bison \
    flex \
    openssl-devel \
    elfutils-libelf-devel \
    qemu-system-x86 \
    qemu-img \
    genisoimage \
    grub2-tools \
    cpio \
    gzip \
    parted \
    curl \
    wget \
    git \
    golang
```

#### Arch Linux
```bash
sudo pacman -S \
    base-devel \
    bc \
    cpio \
    qemu-system-x86 \
    cdrtools \
    grub \
    parted \
    curl \
    wget \
    git \
    go
```

## 🏗️ Building Ziro-OS

### 1. Clone Repository
```bash
git clone https://github.com/ziro-os/ziro-os.git
cd ziro-os
```

### 2. Build Complete System
```bash
# Build everything (kernel, rootfs, tools)
make all

# Optimize for size
make optimize
```

### 3. Create Bootable Images
```bash
# Create bootable disk and ISO images
make image-bootable
```

This creates:
- `images/bootable/output/ziro-os-YYYYMMDD-HHMMSS.img` - Raw disk image
- `images/bootable/output/ziro-os-YYYYMMDD-HHMMSS.qcow2` - QEMU image
- `images/bootable/output/ziro-os-YYYYMMDD-HHMMSS.iso` - ISO for installation

## 🖥️ Running in QEMU

### Quick Test
```bash
# Test the bootable image
make test-qemu-boot
```

### Manual QEMU Commands
```bash
# Boot from disk image
qemu-system-x86_64 \
    -m 1G \
    -drive file=images/bootable/output/ziro-os-*.qcow2,format=qcow2 \
    -netdev user,id=net0 \
    -device e1000,netdev=net0 \
    -nographic

# Boot from ISO
qemu-system-x86_64 \
    -m 1G \
    -cdrom images/bootable/output/ziro-os-*.iso \
    -netdev user,id=net0 \
    -device e1000,netdev=net0 \
    -nographic

# Boot with VNC display
qemu-system-x86_64 \
    -m 1G \
    -drive file=images/bootable/output/ziro-os-*.qcow2,format=qcow2 \
    -netdev user,id=net0 \
    -device e1000,netdev=net0 \
    -vnc :0
```

## 💿 Creating Installation Media

### USB Drive
```bash
# Create bootable USB (requires sudo)
make create-usb

# Or manually:
sudo dd if=images/bootable/output/ziro-os-*.iso of=/dev/sdX bs=4M status=progress
```

### DVD
Burn the ISO file to a DVD using your preferred burning software.

## 💻 Installing to Proxmox VE, Hypervisors & Bare Metal

### 1. Boot from Installation Media
- **Proxmox VE**: Upload `ziro-os-x86_64.iso` to Proxmox local storage. Create a VM with either **SeaBIOS** or **OVMF (UEFI)** and VirtIO SCSI disk.
- **VMware / VirtualBox**: Attach `ziro-os-x86_64.iso` to the virtual CD/DVD drive.
- **Bare Metal**: Burn or `dd` ISO to a USB flash drive (`dd if=ziro-os-x86_64.iso of=/dev/sdX bs=4M status=progress`).
- Boot the system. Ziro-OS boots into the live environment in under 2 seconds.

### 2. Interactive Terminal/TUI Installation
In the live environment or recovery console, run:
```bash
ziro-install
# Or via ziroctl:
ziroctl install
```

The installer will:
1. Scan storage drives (`/dev/vda`, `/dev/sda`, `/dev/nvme0n1`, etc.) and present a numbered selection.
2. Prompt for system hostname (default: `ziro-host`).
3. Prompt for SSH public key (recommending key-based auth and disabling root passwords) or root password.
4. Prompt for optional cloud post-installation user-data script (URL or local script).
5. Partition target disk with GPT (512MB EFI System Partition + Linux Root partition).
6. Format filesystems (`FAT32` for ESP, `ext4` for root).
7. Deploy the Ziro-OS container host filesystem and kernel.
8. Install hybrid UEFI (`x86_64-efi`) and BIOS (`i386-pc`) GRUB bootloaders.
9. Generate persistent `/etc/fstab`, secure SSH configuration, and execute user-data script.

### 3. Automated / Unattended Cloud-Native Installation
For automated installations without interactive prompts:
```bash
# Hands-free installation with SSH key:
ziro-install -d /dev/vda -n ziro-node-1 -k "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5..." -y

# Hands-free with remote cloud user-data bootstrap script:
ziro-install -d /dev/sda -n edge-host -u https://infra.internal/bootstrap.sh -y
```

#### Kernel Command-Line Auto-Installation
You can also trigger unattended installations directly from PXE or GRUB kernel arguments:
```text
linux /boot/vmlinuz ziro.autoinstall ziro.install=/dev/sda ziro.hostname=node1 ziro.userdata=https://example.com/init.sh quiet
```

### 4. First Boot
1. Detach or disconnect the ISO media.
2. Type `reboot` in the terminal.
3. System boots directly from disk into the fast container host with `containerd` active and ready for workloads.

## ☁️ Cloud Deployment

### AWS
```bash
# Build and deploy AWS AMI
make cloud-aws

# Launch instance
aws ec2 run-instances \
    --image-id ami-xxxxxxxxx \
    --instance-type t3.medium \
    --key-name your-key
```

### Azure
```bash
# Build Azure VM image
make cloud-azure

# Create VM
az vm create \
    --resource-group myResourceGroup \
    --name myVM \
    --image ziro-os-latest \
    --admin-username azureuser
```

### Google Cloud
```bash
# Build GCP image
make cloud-gcp

# Create instance
gcloud compute instances create my-vm \
    --image-family=ziro-os \
    --machine-type=e2-medium
```

## 🐳 Container Operations

### After Installation
```bash
# Check system status
ziroctl system status

# Install packages
ziropkg install nginx redis postgresql

# Run containers
ziroctl container run nginx:alpine
ziroctl container run redis:alpine

# List running containers
ziroctl container list
```

### Development Workflow
```bash
# Create new project
ziro-dev init my-app --type=web --language=go

# Build and deploy
cd my-app
ziro-dev build
ziro-dev deploy
```

## 🔧 System Configuration

### Network Configuration
Ziro-OS uses automatic network configuration via DHCP by default. For static configuration:

```bash
# Edit network configuration
vi /etc/network/interfaces

# Restart networking
systemctl restart networking
```

### Container Runtime Configuration
```bash
# Edit containerd configuration
vi /etc/containerd/config.toml

# Restart containerd
systemctl restart containerd
```

### Security Configuration
```bash
# Apply security hardening
make harden

# Check security status
ziroctl security status
```

## 📊 Monitoring

### Built-in Monitoring
```bash
# Install monitoring stack
make monitoring

# View dashboard
/opt/monitoring/dashboard.sh
```

### Access Monitoring Services
- Prometheus: http://localhost:9090
- Node Exporter: http://localhost:9100
- cAdvisor: http://localhost:8080

## 🔍 Troubleshooting

### Boot Issues
1. **System won't boot**: Check BIOS/UEFI settings, ensure secure boot is disabled
2. **Kernel panic**: Boot with recovery mode, check hardware compatibility
3. **No network**: Verify network interface configuration

### Container Issues
1. **Containerd not starting**: Check logs with `journalctl -u containerd`
2. **Images won't pull**: Check network connectivity and DNS
3. **Containers won't start**: Check resource limits and security policies

### Performance Issues
1. **Slow boot**: Check for unnecessary services, optimize kernel config
2. **High memory usage**: Monitor with `ziroctl system resources`
3. **Network latency**: Check CNI configuration and network setup

### Getting Help
- Check logs: `journalctl -f`
- System information: `ziroctl system info`
- Container logs: `ziroctl container logs <container-id>`
- Community support: https://github.com/ziro-os/ziro-os/discussions

## 📋 System Requirements

### Minimum Requirements
- **CPU**: x86_64 (64-bit)
- **RAM**: 512MB (1GB recommended)
- **Storage**: 2GB (4GB recommended)
- **Network**: Ethernet or Wi-Fi adapter

### Recommended Requirements
- **CPU**: Multi-core x86_64
- **RAM**: 2GB or more
- **Storage**: 8GB or more (SSD preferred)
- **Network**: Gigabit Ethernet

### Supported Hardware
- Most modern x86_64 systems
- Virtual machines (VMware, VirtualBox, KVM)
- Cloud instances (AWS, Azure, GCP)
- Container platforms (Docker, Podman)

## 🔄 Updates and Maintenance

### System Updates
```bash
# Update packages
ziropkg update

# Update system components
ziroctl system update
```

### Backup and Recovery
```bash
# Backup configuration
ziroctl config backup

# Restore configuration
ziroctl config restore backup.tar.gz
```

### Monitoring Health
```bash
# System health check
ziroctl system health

# Container health
ziroctl container health
```

This installation guide covers all major deployment scenarios for Ziro-OS. For specific use cases or advanced configurations, refer to the additional documentation in the `docs/` directory.