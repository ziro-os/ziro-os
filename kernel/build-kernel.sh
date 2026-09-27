#!/bin/bash
# Ziro-OS Reproducible Kernel Builder (Docker-based)
# Builds Linux LTS kernel optimized for containers and virtualization.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

RAW_ARCH="${1:-$(uname -m)}"
case "$RAW_ARCH" in
    x86_64|amd64)
        TARGET_ARCH="x86_64"
        KERNEL_ARCH="x86"
        DOCKER_PLATFORM="linux/amd64"
        KERNEL_TARGET="bzImage"
        KERNEL_OUT_SRC="arch/x86/boot/bzImage"
        ;;
    arm64|aarch64)
        TARGET_ARCH="arm64"
        KERNEL_ARCH="arm64"
        DOCKER_PLATFORM="linux/arm64"
        KERNEL_TARGET="Image"
        KERNEL_OUT_SRC="arch/arm64/boot/Image"
        ;;
    *)
        echo "❌ Unsupported architecture: $RAW_ARCH"
        exit 1
        ;;
esac

KERNEL_VER="${KERNEL_VERSION:-6.6.8}"
BUILD_DIR="$REPO_ROOT/build"
KERNEL_BUILD_DIR="$BUILD_DIR/kernel-$TARGET_ARCH"
CONFIG_FILE="$REPO_ROOT/kernel/configs/config-$TARGET_ARCH"

mkdir -p "$BUILD_DIR" "$KERNEL_BUILD_DIR"

echo "=================================================="
echo " Building Linux Kernel $KERNEL_VER for $TARGET_ARCH"
echo " Configuration: $CONFIG_FILE"
echo " Platform:      $DOCKER_PLATFORM"
echo "=================================================="

# Check if configuration exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "❌ Config file not found: $CONFIG_FILE"
    exit 1
fi

# Run Docker-based kernel build
docker run --rm \
    --platform "$DOCKER_PLATFORM" \
    -v "$KERNEL_BUILD_DIR:/build" \
    -v "$CONFIG_FILE:/kernel-config" \
    alpine:latest sh -c "
        set -e
        echo 'Installing kernel build toolchain...'
        apk add --no-cache build-base linux-headers bc bison flex openssl-dev elfutils-dev perl xz bash curl

        cd /build
        if [ ! -d 'linux-$KERNEL_VER' ]; then
            echo 'Downloading Linux kernel $KERNEL_VER...'
            curl -fsSL https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KERNEL_VER.tar.xz | tar -xJ
        fi

        cd linux-$KERNEL_VER
        echo 'Applying Ziro-OS kernel configuration...'
        cp /kernel-config .config
        make ARCH=$KERNEL_ARCH olddefconfig

        echo 'Compiling kernel ($KERNEL_TARGET)...'
        make ARCH=$KERNEL_ARCH -j\$(nproc) $KERNEL_TARGET

        echo 'Copying built kernel image...'
        cp $KERNEL_OUT_SRC /build/vmlinuz
"

# Copy output to canonical location
FINAL_KERNEL="$BUILD_DIR/vmlinuz-$TARGET_ARCH"
cp "$KERNEL_BUILD_DIR/vmlinuz" "$FINAL_KERNEL"
KERNEL_SIZE=$(du -h "$FINAL_KERNEL" | cut -f1)

echo "=================================================="
echo "✅ Kernel built successfully: $FINAL_KERNEL ($KERNEL_SIZE)"
echo "=================================================="
