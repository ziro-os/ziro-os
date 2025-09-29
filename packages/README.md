# Packages

Build recipes and modules for Ziro-OS components.

## Structure
- `cni/` - CNI plugins (bridge, flannel, etc)
- `network/` - Network modules (DHCP, DNS)
- `logging/` - Logging backends
- `storage/` - Volume drivers and storage modules
- `base/` - Core packages (musl, busybox, containerd)

Each package should include:
- `manifest.yaml` - Package metadata
- `build.sh` - Build script
- `install.sh` - Installation script