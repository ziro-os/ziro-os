# Ziro-OS Docker Build System

This directory contains Docker-based build tools for Ziro-OS, designed to solve the missing build tools problem on macOS and provide a consistent build environment across platforms.

## Quick Start

### 1. Demo Container (Fastest)
```bash
# Build a demo container to test Ziro-OS concepts
make docker-build-quick

# Test the demo
docker run -it ziro-os-demo:latest
docker run --rm ziro-os-demo:latest ziroctl version
```

### 2. Full System Build (Recommended)
```bash
# Build complete Ziro-OS system using Docker
make docker-build-iso    # Creates bootable ISO
make docker-build-qemu   # Creates QEMU image
make docker-build-all    # Creates all image types
```

### 3. Container Image
```bash
# Build Ziro-OS as a Docker container
make docker-image

# Run the container
docker run -it --privileged ziro-os:latest
```

## Available Build Scripts

### `build-quick.sh`
- **Purpose**: Creates a demo container for testing Ziro-OS concepts
- **Speed**: Very fast (< 1 minute)
- **Output**: Demo container with mock ziroctl
- **Use case**: Quick testing, demonstrations, CI/CD validation

### `build-in-docker.sh`
- **Purpose**: Full system build using Docker container
- **Speed**: Slow (10-30 minutes)
- **Output**: Bootable ISO, QEMU images, container images
- **Use case**: Production builds, complete system testing

### `build-docker-image.sh`
- **Purpose**: Creates runnable Ziro-OS container
- **Speed**: Medium (5-10 minutes)
- **Output**: Docker container with real Ziro-OS components
- **Use case**: Container orchestration, cloud deployment

### `build-minimal.sh`
- **Purpose**: Minimal build with essential components only
- **Speed**: Medium (5-15 minutes)
- **Output**: Lightweight container
- **Use case**: Resource-constrained environments

### `build-simple.sh`
- **Purpose**: Simple multi-stage build
- **Speed**: Medium (10-20 minutes)
- **Output**: Container with built components
- **Use case**: Development, testing

## Build Outputs

All build outputs are saved to the `output/` directory:

```
output/
├── ziro-os-demo-*.tar           # Demo container
├── ziro-os-*.iso                # Bootable ISO
├── ziro-os-*.qcow2             # QEMU image
├── ziro-os-*.img               # Raw disk image
└── ziro-os-container-*.tar     # Container image
```

## Testing Your Builds

### Demo Container
```bash
# Interactive demo
docker run -it ziro-os-demo:latest

# Command testing
docker run --rm ziro-os-demo:latest ziroctl version
docker run --rm ziro-os-demo:latest ziroctl status
docker run --rm ziro-os-demo:latest ziroctl info
```

### ISO Image
```bash
# Boot in QEMU
qemu-system-x86_64 -m 1024 -cdrom output/ziro-os-*.iso

# Create bootable USB (Linux/macOS)
sudo dd if=output/ziro-os-*.iso of=/dev/sdX bs=4M status=progress
```

### QEMU Image
```bash
# Boot QEMU image
qemu-system-x86_64 -m 1024 output/ziro-os-*.qcow2

# With networking
qemu-system-x86_64 -m 1024 -netdev user,id=net0 -device e1000,netdev=net0 output/ziro-os-*.qcow2
```

### Container Image
```bash
# Load saved container
docker load < output/ziro-os-container-*.tar

# Run with privileges for container runtime
docker run -it --privileged ziro-os:latest

# Test container functionality
docker run --rm ziro-os:latest containerd --version
docker run --rm ziro-os:latest runc --version
```

## Architecture Support

Build for different architectures:

```bash
# ARM64 (Apple Silicon, ARM servers)
TARGET_ARCH=arm64 make docker-build-quick

# x86_64 (Intel/AMD)
TARGET_ARCH=x86_64 make docker-build-quick

# Build all architectures
make kernel-all rootfs-all
TARGET_ARCH=x86_64 make docker-build-iso
TARGET_ARCH=arm64 make docker-build-iso
```

## Troubleshooting

### Docker Not Available
```bash
# macOS
brew install --cask docker

# Ubuntu/Debian
sudo apt-get install docker.io

# Start Docker service
sudo systemctl start docker
```

### Permission Denied
```bash
# Add user to docker group (Linux)
sudo usermod -aG docker $USER
newgrp docker

# Or use sudo
sudo make docker-build-quick
```

### Build Failures
```bash
# Clean everything and retry
make clean
docker system prune -f
make docker-build-quick

# Check Docker logs
docker logs $(docker ps -lq)

# Verbose build
DOCKER_BUILDKIT=0 make docker-build-quick
```

### Missing Output Files
```bash
# Check if build completed
ls -la output/

# Check Docker images
docker images | grep ziro-os

# Manual build steps
./docker/build-quick.sh
```

### Architecture Issues
```bash
# Check current architecture
uname -m

# Force specific architecture
TARGET_ARCH=x86_64 make docker-build-quick

# Use platform-specific build
docker build --platform linux/amd64 ...
```

## Development Workflow

### 1. Quick Development Cycle
```bash
# Make code changes
vim kernel/config.txt

# Quick test
make docker-build-quick
docker run --rm ziro-os-demo:latest ziroctl version
```

### 2. Full Development Cycle
```bash
# Make changes
vim packages/base/containerd.yaml

# Full rebuild
make clean
make docker-build-iso

# Test in QEMU
qemu-system-x86_64 -m 1024 -cdrom output/ziro-os-*.iso
```

### 3. Container Development
```bash
# Build container
make docker-image

# Test container runtime
docker run -it --privileged ziro-os:latest

# Inside container
containerd &
ctr version
```

## CI/CD Integration

### GitHub Actions
```yaml
name: Build Ziro-OS
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build Demo
        run: make docker-build-quick
        
      - name: Test Demo
        run: docker run --rm ziro-os-demo:latest ziroctl version
        
      - name: Build Full System
        run: make docker-build-iso
        
      - name: Upload Artifacts
        uses: actions/upload-artifact@v3
        with:
          name: ziro-os-images
          path: output/
```

### GitLab CI
```yaml
build:
  image: docker:latest
  services:
    - docker:dind
  script:
    - make docker-build-quick
    - docker run --rm ziro-os-demo:latest ziroctl version
  artifacts:
    paths:
      - output/
```

## Performance Optimization

### Build Speed
```bash
# Use BuildKit for faster builds
export DOCKER_BUILDKIT=1

# Parallel builds
make -j$(nproc) kernel-all rootfs-all

# Use specific targets
make docker-build-quick  # Instead of docker-build-all
```

### Resource Usage
```bash
# Limit Docker resources
docker run -m 512m --cpus="1.0" ...

# Clean up between builds
docker system prune -f

# Use multi-stage builds (already implemented)
```

### Caching
```bash
# Don't clean unless necessary
# make clean  # Skip this for faster rebuilds

# Use Docker layer caching
docker build --cache-from ziro-os-builder:latest ...
```

## Advanced Usage

### Custom Configuration
```bash
# Custom version
VERSION=v1.0.0 make docker-build-quick

# Custom features
ENABLE_UEFI=true ENABLE_CLOUD_INIT=true make docker-build-iso

# Custom architecture
TARGET_ARCH=arm64 make docker-build-quick
```

### Multi-Platform Builds
```bash
# Setup buildx for multi-platform
docker buildx create --use

# Build for multiple platforms
docker buildx build --platform linux/amd64,linux/arm64 ...
```

### Registry Integration
```bash
# Tag for registry
docker tag ziro-os-demo:latest myregistry.com/ziro-os:latest

# Push to registry
docker push myregistry.com/ziro-os:latest

# Pull and run
docker run -it myregistry.com/ziro-os:latest
```

## Next Steps

After successful Docker builds:

1. **Deploy to Cloud**: Use generated images with AWS, Azure, GCP
2. **Kubernetes**: Deploy container images to K8s clusters
3. **Physical Hardware**: Burn ISO to USB and install on real hardware
4. **Development**: Use containers for Ziro-OS development and testing
5. **CI/CD**: Integrate builds into your deployment pipeline

For more information:
- [Docker Build Guide](../docs/docker-build-guide.md)
- [Multi-Architecture Guide](../docs/multi-architecture-guide.md)
- [Contributing Guide](../CONTRIBUTING.md)