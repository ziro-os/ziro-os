# Ziro-OS Multi-Architecture Build Guide

This guide covers building Ziro-OS for multiple architectures, with special focus on Mac M2 (Apple Silicon) development and ARM64 support.

## 🏗️ Supported Architectures

### Currently Supported
- **x86_64** (Intel/AMD 64-bit) - Primary target
- **ARM64/AArch64** (Apple Silicon, ARM servers) - Full support

### Planned Support
- **RISC-V** - Future release
- **ARM32** - Future release for IoT/embedded

## 🍎 Mac M2 (Apple Silicon) Setup

### Quick Setup
```bash
# Run the automated setup script
./setup-macos.sh

# Or manual setup:
brew install docker qemu go make wget coreutils gnu-tar
```

### Docker Alternatives for Mac
1. **Docker Desktop** (Official)
2. **Colima** (Lightweight, recommended)
3. **OrbStack** (Modern alternative)

```bash
# Install and start Colima
brew install colima
colima start --arch aarch64 --vm-type=vz --vz-rosetta
```

## 🔧 Build Commands

### Single Architecture Builds

#### For x86_64 (Intel/AMD)
```bash
# Build all components for x86_64
make all TARGET_ARCH=x86_64

# Build specific components
make kernel TARGET_ARCH=x86_64
make rootfs TARGET_ARCH=x86_64
make tools TARGET_ARCH=x86_64

# Build images
make image-advanced TARGET_ARCH=x86_64
```

#### For ARM64 (Apple Silicon, ARM servers)
```bash
# Build all components for ARM64
make all TARGET_ARCH=arm64

# Build specific components
make kernel TARGET_ARCH=arm64
make rootfs TARGET_ARCH=arm64
make tools TARGET_ARCH=arm64

# Build images
make image-advanced TARGET_ARCH=arm64
```

### Multi-Architecture Builds

#### Build for All Architectures
```bash
# Build kernels for all architectures
make kernel-all

# Build rootfs for all architectures
make rootfs-all

# Build tools for all architectures
make tools-all

# Build everything for both architectures
make kernel-all && make rootfs-all && make tools-all
```

#### Convenience Targets
```bash
# Individual architecture targets
make kernel-x86_64 rootfs-x86_64 tools-x86_64
make kernel-arm64 rootfs-arm64 tools-arm64
```

## 🐳 Docker-Based Cross-Compilation

### How It Works
On macOS, Ziro-OS automatically uses Docker for cross-platform builds:

1. **Kernel Build**: Uses Ubuntu container with cross-compilation toolchain
2. **Rootfs Build**: Uses multi-platform Docker images
3. **Image Creation**: Uses QEMU for cross-platform image manipulation

### Docker Configuration
```bash
# Enable multi-platform builds
docker buildx create --name ziro-builder --driver docker-container --bootstrap
docker buildx use ziro-builder

# Verify platform support
docker buildx inspect --bootstrap
```

## 🏃 Quick Start Examples

### Mac M2 Development Workflow
```bash
# 1. Setup (one-time)
./setup-macos.sh

# 2. Build for your Mac (ARM64)
make all TARGET_ARCH=arm64
make image-advanced TARGET_ARCH=arm64

# 3. Build for deployment (x86_64)
make all TARGET_ARCH=x86_64
make image-cloud TARGET_ARCH=x86_64

# 4. Test locally
make test-advanced TARGET_ARCH=arm64
```

### CI/CD Pipeline Simulation
```bash
# Simulate GitHub Actions build
make kernel-all
make rootfs-all
make tools-all

# Build all image types for both architectures
for arch in x86_64 arm64; do
  for type in bootable advanced cloud enhanced; do
    make image-${type} TARGET_ARCH=${arch}
  done
done
```

## 🧪 Testing Multi-Architecture Builds

### QEMU Testing
```bash
# Test x86_64 images on any platform
qemu-system-x86_64 -m 2G -drive file=images/bootable/output/ziro-os-*-x86_64.qcow2,format=qcow2

# Test ARM64 images on any platform
qemu-system-aarch64 -m 2G -cpu cortex-a72 -M virt \
  -drive file=images/bootable/output/ziro-os-*-arm64.qcow2,format=qcow2 \
  -bios /usr/share/qemu-efi-aarch64/QEMU_EFI.fd
```

### Native Testing
```bash
# On Mac M2 (ARM64)
make test-advanced TARGET_ARCH=arm64

# Cross-platform testing
make test-advanced TARGET_ARCH=x86_64  # Uses QEMU emulation
```

## 📦 Image Formats by Architecture

### x86_64 Images
- `ziro-os-*-x86_64.img` - Raw disk image
- `ziro-os-*-x86_64.qcow2` - QEMU compressed image
- `ziro-os-*-x86_64.iso` - Installation ISO
- `ziro-os-aws-*-x86_64.img` - AWS AMI format
- `ziro-os-azure-*-x86_64.vhd` - Azure VHD format
- `ziro-os-gcp-*-x86_64.img` - GCP image format
- `ziro-os-vmware-*-x86_64.vmdk` - VMware format

### ARM64 Images
- `ziro-os-*-arm64.img` - Raw disk image
- `ziro-os-*-arm64.qcow2` - QEMU compressed image
- `ziro-os-*-arm64.iso` - Installation ISO
- `ziro-os-aws-*-arm64.img` - AWS Graviton instances
- `ziro-os-azure-*-arm64.vhd` - Azure ARM VMs
- `ziro-os-gcp-*-arm64.img` - GCP Tau T2A instances
- Cloud formats for ARM64 deployments

## ☁️ Cloud Deployment by Architecture

### AWS Deployment

#### x86_64 Instances
```bash
# Build and upload x86_64 AMI
make image-cloud TARGET_ARCH=x86_64
aws s3 cp images/bootable/output/ziro-os-aws-*-x86_64.img s3://your-bucket/
aws ec2 import-image --description "Ziro-OS x86_64" --disk-containers Format=raw,UserBucket='{S3Bucket=your-bucket,S3Key=ziro-os-aws-*-x86_64.img}'

# Launch x86_64 instance
aws ec2 run-instances --image-id ami-xxxxxxxxx --instance-type t3.medium
```

#### ARM64 Graviton Instances
```bash
# Build and upload ARM64 AMI
make image-cloud TARGET_ARCH=arm64
aws s3 cp images/bootable/output/ziro-os-aws-*-arm64.img s3://your-bucket/
aws ec2 import-image --description "Ziro-OS ARM64" --disk-containers Format=raw,UserBucket='{S3Bucket=your-bucket,S3Key=ziro-os-aws-*-arm64.img}'

# Launch Graviton instance
aws ec2 run-instances --image-id ami-yyyyyyyyy --instance-type t4g.medium
```

### Azure Deployment

#### x86_64 VMs
```bash
make image-cloud TARGET_ARCH=x86_64
az storage blob upload --account-name yourstorageaccount --container-name images \
  --name ziro-os-x86_64.vhd --file images/bootable/output/ziro-os-azure-*-x86_64.vhd
```

#### ARM64 VMs
```bash
make image-cloud TARGET_ARCH=arm64
az storage blob upload --account-name yourstorageaccount --container-name images \
  --name ziro-os-arm64.vhd --file images/bootable/output/ziro-os-azure-*-arm64.vhd
```

### Google Cloud Platform

#### x86_64 Instances
```bash
make image-cloud TARGET_ARCH=x86_64
gsutil cp images/bootable/output/ziro-os-gcp-*-x86_64.img gs://your-bucket/
gcloud compute images create ziro-os-x86_64 --source-uri gs://your-bucket/ziro-os-gcp-*-x86_64.img
```

#### ARM64 Tau T2A Instances
```bash
make image-cloud TARGET_ARCH=arm64
gsutil cp images/bootable/output/ziro-os-gcp-*-arm64.img gs://your-bucket/
gcloud compute images create ziro-os-arm64 --source-uri gs://your-bucket/ziro-os-gcp-*-arm64.img
```

## 🚀 GitHub Actions Automated Builds

### Triggering Builds
```bash
# Create a release tag to trigger full multi-arch build
git tag v1.0.0
git push origin v1.0.0

# This will build:
# - Both x86_64 and ARM64 kernels
# - All image types for both architectures
# - Create GitHub release with all artifacts
```

### Manual Workflow Dispatch
1. Go to GitHub Actions tab
2. Select "Build and Release Ziro-OS" workflow
3. Click "Run workflow"
4. Choose release type: development, release, or hotfix

### Artifacts Available
- **Kernel artifacts**: `kernel-x86_64`, `kernel-arm64`
- **Rootfs artifacts**: `rootfs-x86_64`, `rootfs-arm64`
- **Image artifacts**: `images-{arch}-{type}` for each combination
- **Release assets**: All images with checksums for tagged releases

## 🔧 Development Tips

### Mac M2 Specific
1. **Use Rosetta 2**: Automatically handled by Colima/Docker
2. **Memory allocation**: Give Docker/Colima 8GB+ RAM
3. **Storage**: Use fast SSD for build directories
4. **Parallel builds**: Use `make -j$(nproc)` for faster builds

### Cross-Compilation Tips
1. **Cache builds**: Docker layer caching speeds up rebuilds
2. **Incremental builds**: Only changed components are rebuilt
3. **Multi-stage builds**: Reduces final image size
4. **Build order**: Kernel → Rootfs → Tools → Images

### Performance Optimization
```bash
# Enable Docker BuildKit for faster builds
export DOCKER_BUILDKIT=1

# Use build cache
docker buildx build --cache-from type=local,src=/tmp/.buildx-cache

# Parallel architecture builds
make kernel-x86_64 & make kernel-arm64 & wait
```

## 🐛 Troubleshooting

### Common Issues on Mac M2

#### Docker Not Starting
```bash
# Check Docker/Colima status
colima status

# Restart if needed
colima restart

# Check resources
colima list
```

#### Cross-Platform Build Failures
```bash
# Verify buildx setup
docker buildx ls

# Check platform support
docker buildx inspect --bootstrap

# Clean and rebuild
docker system prune -a
```

#### QEMU Issues
```bash
# Reinstall QEMU
brew reinstall qemu

# Check virtualization support
sysctl kern.hv_support

# Test QEMU
qemu-system-x86_64 --version
qemu-system-aarch64 --version
```

### Build Failures

#### Kernel Build Issues
```bash
# Check dependencies
make kernel TARGET_ARCH=x86_64 2>&1 | grep -i error

# Clean and retry
rm -rf kernel/build-*
make kernel TARGET_ARCH=x86_64
```

#### Rootfs Build Issues
```bash
# Check Docker platform support
docker run --rm --platform linux/arm64 ubuntu:22.04 uname -m

# Verify cross-compilation tools
docker run --rm --platform linux/arm64 ubuntu:22.04 apt list --installed | grep gcc
```

### Performance Issues

#### Slow Builds
```bash
# Increase Docker resources (Docker Desktop)
# Or for Colima:
colima stop
colima start --cpu 4 --memory 8 --disk 100

# Use parallel builds
make -j$(nproc) kernel-all
```

#### Large Image Sizes
```bash
# Optimize images
make optimize TARGET_ARCH=x86_64

# Clean build artifacts
make clean

# Use compressed formats
qemu-img convert -f raw -O qcow2 -c input.img output.qcow2
```

## 📚 Additional Resources

- [Docker Multi-Platform Builds](https://docs.docker.com/build/building/multi-platform/)
- [QEMU User Emulation](https://qemu.readthedocs.io/en/latest/user/main.html)
- [ARM64 Linux Kernel](https://www.kernel.org/doc/html/latest/arm64/index.html)
- [Apple Silicon Development](https://developer.apple.com/documentation/apple-silicon)

## 🎯 Next Steps

1. **Try the setup**: Run `./setup-macos.sh` on your Mac M2
2. **Build for ARM64**: `make all TARGET_ARCH=arm64`
3. **Test locally**: `make test-advanced TARGET_ARCH=arm64`
4. **Deploy to cloud**: Use ARM64 images for cost-effective cloud instances
5. **Contribute**: Help us add RISC-V and ARM32 support!

Happy building! 🚀