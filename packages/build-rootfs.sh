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
    
    # Copy tracked usr skeleton (e.g. udhcpc default script)
    if [ -d "$REPO_ROOT/rootfs/usr" ]; then
        mkdir -p "$target/usr"
        cp -r "$REPO_ROOT/rootfs/usr/"* "$target/usr/"
        chmod +x "$target/usr/share/udhcpc/default.script" 2>/dev/null || true
    fi
    mkdir -p "$target/lib/apk/db" "$target/etc/apk"
    touch "$target/lib/apk/db/installed"
    touch "$target/etc/apk/world"
    local apk_arch="x86_64"
    if [ "$TARGET_ARCH" = "arm64" ] || [ "$TARGET_ARCH" = "aarch64" ]; then
        apk_arch="aarch64"
    fi
    echo "$apk_arch" > "$target/etc/apk/arch"

    # Ensure TLS certificates exist for HTTPS package downloads
    mkdir -p "$target/etc/ssl/certs"
    if [ ! -f "$target/etc/ssl/certs/ca-certificates.crt" ]; then
        docker run --rm --platform "$DOCKER_PLATFORM" alpine:latest cat /etc/ssl/certs/ca-certificates.crt > "$target/etc/ssl/certs/ca-certificates.crt" 2>/dev/null || true
    fi
    if [ -f "$target/etc/ssl/certs/ca-certificates.crt" ]; then
        (cd "$target/etc/ssl" && ln -sf certs/ca-certificates.crt cert.pem)
    fi

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
            # Do NOT create init symlink in /bin
            if [ "$app" != "init" ]; then
                ln -sf busybox "$app"
            fi
        done
        cd /rootfs/sbin
        # Note: init is intentionally excluded here so it never overwrites busybox!
        for app in halt poweroff reboot ifconfig route sysctl ip insmod rmmod modprobe lsmod; do
            ln -sf ../bin/busybox "$app"
        done
        rm -f /rootfs/init /rootfs/sbin/init /rootfs/bin/init
    '
}

install_busybox "$ROOTFS_MINIMAL"
install_busybox "$ROOTFS_FULL"
echo "✓ BusyBox utilities installed"

# --- 2. Build & Install ziroctl and ziropkg ---
echo "--- [2/6] Compiling ziroctl and ziropkg ($GOARCH) ---"
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

ZIROPKG_BIN="$REPO_ROOT/bin/ziropkg-$TARGET_ARCH"
(
    cd "$REPO_ROOT/tools/ziropkg"
    CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" go build -ldflags="-s -w" -o "$ZIROPKG_BIN" .
)
cp "$ZIROPKG_BIN" "$ROOTFS_MINIMAL/usr/bin/ziropkg"
cp "$ZIROPKG_BIN" "$ROOTFS_MINIMAL/bin/ziropkg"
cp "$ZIROPKG_BIN" "$ROOTFS_FULL/usr/bin/ziropkg"
cp "$ZIROPKG_BIN" "$ROOTFS_FULL/bin/ziropkg"

# Fetch & install static apk backend
APK_BIN="$DOWNLOAD_DIR/apk-$TARGET_ARCH"
if [ ! -f "$APK_BIN" ]; then
    echo "Extracting static APK package manager for $TARGET_ARCH..."
    docker run --rm --platform "$DOCKER_PLATFORM" -v "$DOWNLOAD_DIR:/out" alpine:latest sh -c \
        "apk add --no-cache apk-tools-static >/dev/null 2>&1 && cp /sbin/apk.static /out/apk-$TARGET_ARCH"
    chmod +x "$APK_BIN"
fi
cp "$APK_BIN" "$ROOTFS_MINIMAL/sbin/apk"
cp "$APK_BIN" "$ROOTFS_MINIMAL/usr/bin/apk"
cp "$APK_BIN" "$ROOTFS_FULL/sbin/apk"
cp "$APK_BIN" "$ROOTFS_FULL/usr/bin/apk"
echo "✓ ziroctl, ziropkg, and apk package backend installed"

# --- 3. Build & Install ziro-init (PID 1) ---
echo "--- [3/5] Building ziro-init PID 1 supervisor ($TARGET_ARCH) ---"
INIT_BIN="$REPO_ROOT/init/ziro-init-$TARGET_ARCH"
if [ ! -f "$INIT_BIN" ]; then
    make -C "$REPO_ROOT/init" TARGET_ARCH="$TARGET_ARCH"
fi
rm -f "$ROOTFS_FULL/init" "$ROOTFS_FULL/sbin/init" "$ROOTFS_FULL/bin/init"
cp "$INIT_BIN" "$ROOTFS_FULL/init"
cp "$INIT_BIN" "$ROOTFS_FULL/sbin/init"
chmod +x "$ROOTFS_FULL/init" "$ROOTFS_FULL/sbin/init"

# Ensure busybox is untouched
if cmp -s "$ROOTFS_FULL/bin/busybox" "$INIT_BIN"; then
    echo "❌ FATAL: /bin/busybox was overwritten by ziro-init!"
    exit 1
fi

# For minimal rootfs (Docker base), /bin/sh is entrypoint, but provide init as option
rm -f "$ROOTFS_MINIMAL/sbin/ziro-init"
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

# --- 5. Install Musl-Native Container Runtime for Host OS ---
echo "--- [5/5] Installing musl-native containerd, runc, and CNI plugins for Host OS ---"
docker run --rm --platform "$DOCKER_PLATFORM" -v "$ROOTFS_FULL:/rootfs" alpine:latest sh -c '
    apk --root /rootfs --initdb add --no-cache ca-certificates containerd containerd-ctr runc cni-plugins
    mkdir -p /rootfs/opt/cni/bin
    if [ -d /rootfs/usr/libexec/cni ]; then
        cp -r /rootfs/usr/libexec/cni/* /rootfs/opt/cni/bin/ 2>/dev/null || true
    fi
'

# Re-affirm ziro-init and BusyBox after package additions
rm -f "$ROOTFS_FULL/init" "$ROOTFS_FULL/sbin/init"
cp "$INIT_BIN" "$ROOTFS_FULL/init"
cp "$INIT_BIN" "$ROOTFS_FULL/sbin/init"
chmod +x "$ROOTFS_FULL/init" "$ROOTFS_FULL/sbin/init"

if cmp -s "$ROOTFS_FULL/bin/busybox" "$INIT_BIN"; then
    echo "❌ FATAL: /bin/busybox was overwritten by ziro-init!"
    exit 1
fi

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
