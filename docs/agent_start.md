# Agent Start Guide

This document explains how to boot, build, and test Ziro-OS after the initial scaffold.

## Project Structure

The Ziro-OS project is organized into these key directories:

- `kernel/` - Kernel configuration and build files
- `rootfs/` - Minimal userland filesystem  
- `packages/` - Package build recipes (musl, busybox, containerd)
- `containerd/` - Container runtime integration
- `images/` - Image building scripts (QEMU, cloud)
- `tools/` - CLI utilities (ziroctl)
- `tests/` - Test harnesses and smoke tests

## Quick Start

### 1. Build the System
```bash
make all          # Build kernel, rootfs, and tools
make image-qemu   # Create bootable QEMU image
```

### 2. Run Tests
```bash
make test-smoke   # Basic boot and container test
```

### 3. Development
```bash
make dev-qemu     # Start interactive QEMU session
```

## Key Components

### Init System
- Minimal init script at `rootfs/etc/init`
- Mounts essential filesystems
- Starts containerd daemon
- Provides basic shell access

### Container Runtime
- Containerd as core runtime
- Configuration in `rootfs/etc/containerd/config.toml`
- OCI runtime support (runc)
- Docker/Podman compatibility layers

### Package System
- YAML-based package manifests
- Build scripts for core packages (musl, busybox, containerd)
- Static linking preferred for minimal dependencies

### Testing
- Smoke tests boot QEMU and verify basic functionality
- Container tests validate pull/run operations
- Network and storage tests ensure CNI/volume functionality

## Next Steps

1. Implement actual kernel compilation in Makefile
2. Add real package building (download, compile, install)
3. Integrate containerd binary and configuration
4. Enhance ziroctl with containerd API integration
5. Add CNI networking modules
6. Implement cloud image builders

## Architecture Notes

- Target < 50MB total image size
- Immutable root filesystem design
- Container-first philosophy
- Modular plugin architecture
- Security hardening (seccomp, capabilities)

The scaffold provides a solid foundation for building a minimal, container-native OS. Each component can now be iteratively developed and tested.