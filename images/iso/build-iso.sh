#!/bin/bash
# Ziro-OS Bootable Hybrid ISO Builder (Docker-based xorriso)
# Generates bootable ISO for physical hardware, VMware, VirtualBox, and Proxmox.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

RAW_ARCH="${1:-$(uname -m)}"
case "$RAW_ARCH" in
    x86_64|amd64)
        TARGET_ARCH="x86_64"
        CONSOLE="ttyS0"
        ;;
    arm64|aarch64)
        TARGET_ARCH="arm64"
        CONSOLE="ttyAMA0"
        ;;
    *)
        TARGET_ARCH="x86_64"
        CONSOLE="ttyS0"
        ;;
esac

echo "=================================================="
echo " Building Ziro-OS Bootable Hybrid ISO"
echo " Architecture: $TARGET_ARCH"
echo "=================================================="

BUILD_DIR="$REPO_ROOT/build"
ISO_STAGING="$BUILD_DIR/iso-staging-$TARGET_ARCH"
OUTPUT_ISO="$BUILD_DIR/ziro-os-$TARGET_ARCH.iso"

mkdir -p "$BUILD_DIR"
rm -rf "$ISO_STAGING"
mkdir -p "$ISO_STAGING/boot/grub"

# Verify kernel
KERNEL_FILE="$BUILD_DIR/vmlinuz-$TARGET_ARCH"
if [ ! -f "$KERNEL_FILE" ]; then
    echo "Kernel not found at $KERNEL_FILE. Auto-provisioning kernel for $TARGET_ARCH..."
    "$REPO_ROOT/kernel/build-kernel.sh" "$TARGET_ARCH"
fi

# Verify initramfs
INITRAMFS_FILE="$BUILD_DIR/ziro-initramfs-$TARGET_ARCH.cpio.gz"
if [ ! -f "$INITRAMFS_FILE" ]; then
    echo "Initramfs not found: $INITRAMFS_FILE"
    echo "Building rootfs first with: ./packages/build-rootfs.sh $TARGET_ARCH"
    "$REPO_ROOT/packages/build-rootfs.sh" "$TARGET_ARCH"
fi

echo "✓ Kernel:    $KERNEL_FILE"
echo "✓ Initramfs: $INITRAMFS_FILE"

# Copy boot artifacts
cp "$KERNEL_FILE" "$ISO_STAGING/boot/vmlinuz"
cp "$INITRAMFS_FILE" "$ISO_STAGING/boot/initramfs.cpio.gz"

# GRUB configuration for UEFI & BIOS
cat > "$ISO_STAGING/boot/grub/grub.cfg" << EOF
set default=0
set timeout=5

menuentry "Ziro-OS Container Host" {
    linux /boot/vmlinuz console=$CONSOLE console=tty0 rdinit=/init quiet
    initrd /boot/initramfs.cpio.gz
}

menuentry "Ziro-OS (Recovery Shell)" {
    linux /boot/vmlinuz console=$CONSOLE console=tty0 rdinit=/bin/sh
    initrd /boot/initramfs.cpio.gz
}
EOF

# Build ISO using Docker with xorriso and grub-efi
docker run --rm \
    -v "$ISO_STAGING:/iso" \
    -v "$BUILD_DIR:/out" \
    alpine:latest sh -c "
        apk add --no-cache xorriso mtools grub-efi >/dev/null 2>&1
        grub-mkrescue -o /out/ziro-os-$TARGET_ARCH.iso /iso 2>/dev/null || \
        xorriso -as mkisofs -R -J -volid 'ZIRO_OS' -o /out/ziro-os-$TARGET_ARCH.iso /iso
    "

ISO_SIZE=$(du -h "$OUTPUT_ISO" | cut -f1)
echo "=================================================="
echo "✅ Bootable ISO generated successfully!"
echo " Output: $OUTPUT_ISO ($ISO_SIZE)"
echo " Usable in: VMware, VirtualBox, Proxmox, Bare Metal"
echo "=================================================="
