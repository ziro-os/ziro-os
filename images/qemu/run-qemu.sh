#!/bin/bash
# Universal Cross-Platform QEMU Boot Runner for Ziro-OS
# Supports both ARM64 and x86_64 with hardware acceleration where available.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

HOST_OS="$(uname -s)"
HOST_ARCH="$(uname -m)"

case "$HOST_ARCH" in
    x86_64|amd64)
        DEFAULT_ARCH="x86_64"
        ;;
    arm64|aarch64)
        DEFAULT_ARCH="arm64"
        ;;
    *)
        DEFAULT_ARCH="x86_64"
        ;;
esac

TARGET_ARCH="${1:-$DEFAULT_ARCH}"
case "$TARGET_ARCH" in
    x86_64|amd64)
        TARGET_ARCH="x86_64"
        QEMU_BIN="qemu-system-x86_64"
        MACHINE="q35"
        CONSOLE="ttyS0"
        NET_DEV="virtio-net-pci"
        ;;
    arm64|aarch64)
        TARGET_ARCH="arm64"
        QEMU_BIN="qemu-system-aarch64"
        MACHINE="virt"
        CONSOLE="ttyAMA0"
        NET_DEV="virtio-net-pci"
        ;;
esac

echo "=================================================="
echo " Ziro-OS QEMU Virtual Machine Runner"
echo " Host OS:       $HOST_OS ($HOST_ARCH)"
echo " Target Arch:   $TARGET_ARCH"
echo " QEMU Binary:   $QEMU_BIN"
echo "=================================================="

# Check for QEMU binary
if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
    echo "❌ $QEMU_BIN not found in PATH."
    if [ "$HOST_OS" = "Darwin" ]; then
        echo "Install with: brew install qemu"
    else
        echo "Install with: sudo apt-get install qemu-system"
    fi
    exit 1
fi

# Locate Kernel
KERNEL_IMAGE=""
for candidate in \
    "$REPO_ROOT/build/vmlinuz-$TARGET_ARCH" \
    "$REPO_ROOT/kernel/bzImage-$TARGET_ARCH" \
    "$REPO_ROOT/kernel/bzImage"; do
    if [ -f "$candidate" ]; then
        # Check architecture if file command is available
        if file "$candidate" | grep -qi -E "(ARM|aarch64)" && [ "$TARGET_ARCH" = "x86_64" ]; then
            continue
        fi
        if file "$candidate" | grep -qi -E "(x86|x-86)" && [ "$TARGET_ARCH" = "arm64" ]; then
            continue
        fi
        KERNEL_IMAGE="$candidate"
        break
    fi
done

if [ -z "$KERNEL_IMAGE" ]; then
    echo "❌ No compatible kernel image found for $TARGET_ARCH."
    echo "Build the kernel first with: make kernel TARGET_ARCH=$TARGET_ARCH"
    exit 1
fi

# Locate Initramfs
INITRAMFS_IMAGE="$REPO_ROOT/build/ziro-initramfs-$TARGET_ARCH.cpio.gz"
if [ ! -f "$INITRAMFS_IMAGE" ]; then
    echo "Initramfs not found: $INITRAMFS_IMAGE"
    echo "Building rootfs first with: ./packages/build-rootfs.sh $TARGET_ARCH"
    "$REPO_ROOT/packages/build-rootfs.sh" "$TARGET_ARCH"
fi

echo "✓ Kernel:    $KERNEL_IMAGE"
echo "✓ Initramfs: $INITRAMFS_IMAGE"

# Acceleration & CPU configuration
QEMU_ACCEL=""
QEMU_CPU=""
if [ "$HOST_OS" = "Darwin" ] && [ "$HOST_ARCH" = "$TARGET_ARCH" ] && [ "$TARGET_ARCH" = "arm64" ]; then
    QEMU_ACCEL="-accel hvf"
    QEMU_CPU="-cpu host"
elif [ "$HOST_OS" = "Linux" ] && [ "$HOST_ARCH" = "$TARGET_ARCH" ] && [ -e /dev/kvm ]; then
    QEMU_ACCEL="-enable-kvm"
    QEMU_CPU="-cpu host"
else
    if [ "$TARGET_ARCH" = "arm64" ]; then
        QEMU_CPU="-cpu cortex-a72"
    else
        QEMU_CPU="-cpu qemu64"
    fi
fi

echo ""
echo "🚀 Booting Ziro-OS microVM..."
echo "💡 Press Ctrl+A, then X to exit QEMU at any time."
echo ""
sleep 1

MEMORY="${MEMORY:-2048M}"

exec "$QEMU_BIN" \
    -machine "$MACHINE" \
    $QEMU_ACCEL \
    $QEMU_CPU \
    -m "$MEMORY" \
    -kernel "$KERNEL_IMAGE" \
    -initrd "$INITRAMFS_IMAGE" \
    -append "console=$CONSOLE rdinit=/init ramdisk_size=2097152 quiet panic=1" \
    -nographic \
    -netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::8080-:80 \
    -device "$NET_DEV,netdev=net0" \
    -no-reboot
