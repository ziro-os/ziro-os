# Docker Compatibility

Docker Engine compatibility layer for Ziro-OS.

This module provides Docker CLI compatibility by translating Docker API calls to containerd operations.

## Components
- `docker-shim` - Docker API to containerd translator
- `docker` - Docker CLI wrapper script