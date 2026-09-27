#!/bin/bash
# Ziro-OS Robust Multi-Architecture Rootfs Builder
# Creates both minimal container base (< 10MB) and full container host OS initramfs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Architecture normalization
RAW_ARCH="${1:-$(uname -m)}"
case "$RAW_ARCH" in
    x86_64|amd64)
        TARGET_ARCH="x86_64"
        GOARCH="amd64"
        DOCKER_PLATFORM="linux/amd64"
        ALPINE_ARCH="x86_64"
        ;;
    arm64|aarch64)
        TARGET_ARCH="arm64"
        GOARCH="arm64"
        DOCKER_PLATFORM="linux/arm64"
        ALPINE_ARCH="aarch64"
        ;;
    *)
        echo "❌ Unsupported architecture: $RAW_ARCH"
        exit 1
        ;;
esac

echo "=================================================="
echo " Building Ziro-OS Rootfs"
echo " Target Architecture: $TARGET_ARCH ($GOARCH)"
echo " Platform: $DOCKER_PLATFORM"
echo "=================================================="

BUILD_DIR="$REPO_ROOT/build"
DOWNLOAD_DIR="$BUILD_DIR/downloads"
ROOTFS_MINIMAL="$BUILD_DIR/rootfs-minimal-$TARGET_ARCH"
ROOTFS_FULL="$BUILD_DIR/rootfs-full-$TARGET_ARCH"

mkdir -p "$BUILD_DIR" "$DOWNLOAD_DIR"
rm -rf "$ROOTFS_MINIMAL" "$ROOTFS_FULL"
mkdir -p "$ROOTFS_MINIMAL" "$ROOTFS_FULL"

# Helper for creating standard Linux directory layout
setup_layout() {
    local target="$1"
    mkdir -p "$target"/{bin,sbin,usr/bin,usr/sbin,lib,usr/lib}
    mkdir -p "$target"/{etc,var/log,var/lib/containerd,var/lib/containers,run,tmp}
    mkdir -p "$target"/{dev,proc,sys,mnt,opt/cni/bin,home,root}
    chmod 1777 "$target/tmp"
    chmod 0700 "$target/root"

    # Copy tracked etc configuration skeleton
    cp -r "$REPO_ROOT/rootfs/etc/"* "$target/etc/"
    
    # Update architecture in ziro-release
    sed -i.bak "s/ARCH=\".*\"/ARCH=\"$TARGET_ARCH\"/g" "$target/etc/ziro-release" 2>/dev/null || true
    rm -f "$target/etc/ziro-release.bak"
}

setup_layout "$ROOTFS_MINIMAL"
setup_layout "$ROOTFS_FULL"

echo "✓ Skeleton directories and configurations prepared"

# --- 1. Fetch & Install BusyBox ---
echo "--- [1/5] Installing BusyBox ($TARGET_ARCH) ---"
BUSYBOX_BIN="$DOWNLOAD_DIR/busybox-$TARGET_ARCH"
if [ ! -f "$BUSYBOX_BIN" ]; then
    echo "Extracting static BusyBox for $TARGET_ARCH via Docker Alpine..."
    docker run --rm --platform "$DOCKER_PLATFORM" -v "$DOWNLOAD_DIR:/out" alpine:latest sh -c \
        "apk add --no-cache busybox-static >/dev/null 2>&1 && cp /bin/busybox.static /out/busybox-$TARGET_ARCH || cp /bin/busybox /out/busybox-$TARGET_ARCH"
    chmod +x "$BUSYBOX_BIN"
fi

install_busybox() {
    local target="$1"
    cp "$BUSYBOX_BIN" "$target/bin/busybox"
    chmod +x "$target/bin/busybox"
    # Create clean relative symlinks
    docker run --rm --platform "$DOCKER_PLATFORM" -v "$target:/rootfs" alpine:latest sh -c '
        cd /rootfs/bin
        for app in $(./busybox --list); do
            ln -sf busybox "$app"
        done
        cd /rootfs/sbin
        for app in halt poweroff reboot init ifconfig route sysctl ip insmod rmmod modprobe lsmod; do
            ln -sf ../bin/busybox "$app"
        done
    '
}

install_busybox "$ROOTFS_MINIMAL"
install_busybox "$ROOTFS_FULL"
echo "✓ BusyBox utilities installed"

# --- 2. Build & Install ziroctl ---
echo "--- [2/5] Compiling ziroctl ($GOARCH) ---"
mkdir -p "$REPO_ROOT/bin"
ZIROCTL_BIN="$REPO_ROOT/bin/ziroctl-$TARGET_ARCH"
(
    cd "$REPO_ROOT/tools/ziroctl"
    CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" go build -ldflags="-s -w" -o "$ZIROCTL_BIN" .
)
cp "$ZIROCTL_BIN" "$ROOTFS_MINIMAL/usr/bin/ziroctl"
cp "$ZIROCTL_BIN" "$ROOTFS_MINIMAL/bin/ziroctl"
cp "$ZIROCTL_BIN" "$ROOTFS_FULL/usr/bin/ziroctl"
cp "$ZIROCTL_BIN" "$ROOTFS_FULL/bin/ziroctl"
echo "✓ ziroctl CLI installed"

# --- 3. Build & Install ziro-init (PID 1) ---
echo "--- [3/5] Building ziro-init PID 1 supervisor ($TARGET_ARCH) ---"
INIT_BIN="$REPO_ROOT/init/ziro-init-$TARGET_ARCH"
if [ ! -f "$INIT_BIN" ]; then
    make -C "$REPO_ROOT/init" TARGET_ARCH="$TARGET_ARCH"
fi
cp "$INIT_BIN" "$ROOTFS_FULL/init"
cp "$INIT_BIN" "$ROOTFS_FULL/sbin/init"
chmod +x "$ROOTFS_FULL/init" "$ROOTFS_FULL/sbin/init"

# For minimal rootfs (Docker base), /bin/sh is entrypoint, but provide init as option
cp "$INIT_BIN" "$ROOTFS_MINIMAL/sbin/ziro-init"
chmod +x "$ROOTFS_MINIMAL/sbin/ziro-init"
echo "✓ ziro-init supervisor installed"

# --- 4. Package Minimal Docker Base Rootfs (< 10MB) ---
echo "--- [4/5] Packaging Minimal Docker Base Rootfs ---"
MINIMAL_TAR="$BUILD_DIR/ziro-rootfs-$TARGET_ARCH.tar.gz"
(
    cd "$ROOTFS_MINIMAL"
    tar --exclude='./dev/*' -czf "$MINIMAL_TAR" .
)
MINIMAL_SIZE=$(du -h "$MINIMAL_TAR" | cut -f1)
echo "✅ Minimal Base Rootfs archive: $MINIMAL_TAR ($MINIMAL_SIZE)"

# --- 5. Install Container Runtime for Host OS ---
echo "--- [5/5] Installing containerd, runc, and CNI plugins for Host OS ---"
CONTAINERD_VER="1.7.13"
RUNC_VER="v1.1.12"
CNI_VER="v1.4.0"

# Fetch containerd
CONTAINERD_TAR="$DOWNLOAD_DIR/containerd-${CONTAINERD_VER}-linux-${GOARCH}.tar.gz"
if [ ! -f "$CONTAINERD_TAR" ]; then
    echo "Downloading containerd $CONTAINERD_VER..."
    curl -fsSL "https://github.com/containerd/containerd/releases/download/v${CONTAINERD_VER}/containerd-${CONTAINERD_VER}-linux-${GOARCH}.tar.gz" -o "$CONTAINERD_TAR"
fi
tar -xzf "$CONTAINERD_TAR" -C "$ROOTFS_FULL/usr"
rm -f "$ROOTFS_FULL/usr/bin/containerd-stress"

# Fetch runc
RUNC_BIN="$DOWNLOAD_DIR/runc-${RUNC_VER}-${GOARCH}"
if [ ! -f "$RUNC_BIN" ]; then
    echo "Downloading runc $RUNC_VER..."
    curl -fsSL "https://github.com/opencontainers/runc/releases/download/${RUNC_VER}/runc.${GOARCH}" -o "$RUNC_BIN"
    chmod +x "$RUNC_BIN"
fi
cp "$RUNC_BIN" "$ROOTFS_FULL/usr/bin/runc"
chmod +x "$ROOTFS_FULL/usr/bin/runc"

# Fetch CNI plugins
CNI_TAR="$DOWNLOAD_DIR/cni-plugins-linux-${GOARCH}-${CNI_VER}.tgz"
if [ ! -f "$CNI_TAR" ]; then
    echo "Downloading CNI plugins $CNI_VER..."
    curl -fsSL "https://github.com/containernetworking/plugins/releases/download/${CNI_VER}/cni-plugins-linux-${GOARCH}-${CNI_VER}.tgz" -o "$CNI_TAR"
fi
tar -xzf "$CNI_TAR" -C "$ROOTFS_FULL/opt/cni/bin"

# Package Full Host OS Initramfs
FULL_INITRAMFS="$BUILD_DIR/ziro-initramfs-$TARGET_ARCH.cpio.gz"
(
    cd "$ROOTFS_FULL"
    find . | cpio -o -H newc | gzip -9 > "$FULL_INITRAMFS"
)
INITRAMFS_SIZE=$(du -h "$FULL_INITRAMFS" | cut -f1)
echo "✅ Full Container OS Initramfs: $FULL_INITRAMFS ($INITRAMFS_SIZE)"

echo "=================================================="
echo " Rootfs build completed successfully for $TARGET_ARCH!"
echo " 1. Minimal Docker base: $MINIMAL_TAR ($MINIMAL_SIZE)"
echo " 2. Full OS Initramfs:   $FULL_INITRAMFS ($INITRAMFS_SIZE)"
echo "=================================================="
