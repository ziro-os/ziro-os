#!/bin/bash
# Ziro-OS Reproducible Kernel Builder (Docker-based)
# Builds or extracts Linux LTS kernel optimized for containers and virtualization.

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
        ALIAS_ARCH="amd64"
        ;;
    arm64|aarch64)
        TARGET_ARCH="arm64"
        KERNEL_ARCH="arm64"
        DOCKER_PLATFORM="linux/arm64"
        KERNEL_TARGET="Image"
        KERNEL_OUT_SRC="arch/arm64/boot/Image"
        ALIAS_ARCH="aarch64"
        ;;
    *)
        echo "❌ Unsupported architecture: $RAW_ARCH"
        exit 1
        ;;
esac

BUILD_DIR="$REPO_ROOT/build"
ALPINE_IMAGE="${ALPINE_IMAGE:-alpine:3.24}"
FINAL_KERNEL="$BUILD_DIR/vmlinuz-$TARGET_ARCH"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

mkdir -p "$BUILD_DIR"

# Reuse existing kernel if present and not forced
if [ -s "$FINAL_KERNEL" ] && [ "${FORCE_KERNEL_BUILD:-0}" != "1" ] && [ "${BUILD_FROM_SOURCE:-0}" != "1" ]; then
    echo "✓ Linux kernel already exists: $FINAL_KERNEL ($(du -h "$FINAL_KERNEL" | cut -f1))"
    ln -sf "vmlinuz-$TARGET_ARCH" "$BUILD_DIR/vmlinuz-$ALIAS_ARCH"
    exit 0
fi

BUILD_FROM_SOURCE="${BUILD_FROM_SOURCE:-0}"

if [ "$BUILD_FROM_SOURCE" = "1" ]; then
    KERNEL_VER="${KERNEL_VERSION:-6.6.8}"
    KERNEL_BUILD_DIR="$BUILD_DIR/kernel-$TARGET_ARCH"
    CONFIG_FILE="$REPO_ROOT/kernel/configs/config-$TARGET_ARCH"

    mkdir -p "$KERNEL_BUILD_DIR"

    echo "=================================================="
    echo " Compiling Linux Kernel $KERNEL_VER from source for $TARGET_ARCH"
    echo " Configuration: $CONFIG_FILE"
    echo " Platform:      $DOCKER_PLATFORM"
    echo "=================================================="

    if [ ! -f "$CONFIG_FILE" ]; then
        echo "❌ Config file not found: $CONFIG_FILE"
        exit 1
    fi

    docker run --rm \
        --platform "$DOCKER_PLATFORM" \
        -v "$KERNEL_BUILD_DIR:/build" \
        -v "$CONFIG_FILE:/kernel-config" \
        -e HOST_UID="$HOST_UID" \
        -e HOST_GID="$HOST_GID" \
        $ALPINE_IMAGE sh -c "
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

            echo 'Building and installing modules...'
            rm -rf /build/modroot
            make -s ARCH=$KERNEL_ARCH kernelrelease > /build/kernel.release
            if grep -q '^CONFIG_MODULES=y' .config; then
                make ARCH=$KERNEL_ARCH -j\$(nproc) modules
                make ARCH=$KERNEL_ARCH INSTALL_MOD_PATH=/build/modroot INSTALL_MOD_STRIP=1 modules_install
            fi
            mkdir -p /build/modroot/lib/modules/\$(cat /build/kernel.release)

            echo 'Copying built kernel image...'
            cp $KERNEL_OUT_SRC /build/vmlinuz
            chown -R \${HOST_UID}:\${HOST_GID} /build/vmlinuz /build/modroot /build/kernel.release
        "

    cp "$KERNEL_BUILD_DIR/vmlinuz" "$FINAL_KERNEL"
    cp "$KERNEL_BUILD_DIR/kernel.release" "$BUILD_DIR/kernel-release-$TARGET_ARCH"
    echo "Note: build the rootfs with BUILD_FROM_SOURCE=1 too, so it ships this kernel's modules."
else
    echo "=================================================="
    echo " Provisioning Container-Optimized Linux Kernel for $TARGET_ARCH"
    echo " Mode:     Pre-compiled Linux Virt LTS"
    echo " Platform: $DOCKER_PLATFORM"
    echo "=================================================="

    docker run --rm \
        --platform "$DOCKER_PLATFORM" \
        -v "$BUILD_DIR:/out" \
        -e HOST_UID="$HOST_UID" \
        -e HOST_GID="$HOST_GID" \
        -e TARGET_ARCH="$TARGET_ARCH" \
        $ALPINE_IMAGE sh -c '
            set -e
            echo "Fetching linux-virt package for container host..."
            apk add --no-cache linux-virt >/dev/null 2>&1
            cp /boot/vmlinuz-virt "/out/vmlinuz-${TARGET_ARCH}"
            ls /lib/modules > "/out/kernel-release-${TARGET_ARCH}"
            chown "${HOST_UID}:${HOST_GID}" "/out/vmlinuz-${TARGET_ARCH}" "/out/kernel-release-${TARGET_ARCH}"
        '
fi

ln -sf "vmlinuz-$TARGET_ARCH" "$BUILD_DIR/vmlinuz-$ALIAS_ARCH"
KERNEL_SIZE=$(du -h "$FINAL_KERNEL" | cut -f1)

echo "=================================================="
echo "✅ Kernel ready: $FINAL_KERNEL ($KERNEL_SIZE)"
echo "=================================================="
