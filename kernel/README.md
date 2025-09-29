# Kernel

This directory contains kernel sources, patches, and configuration files for Ziro-OS.

## Structure
- `config/` - Kernel configuration files for different target platforms
- `patches/` - Custom patches for minimal kernel build
- `linux/` - Linux kernel source or submodule (if using Linux)

## Build
Run `make kernel` from project root to build the kernel with Ziro-OS optimizations.