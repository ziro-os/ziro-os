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

# Bundle rootfs archive on ISO if available for fast offline disk installation
mkdir -p "$ISO_STAGING/ziro"
if [ -f "$BUILD_DIR/ziro-rootfs-$TARGET_ARCH.tar.gz" ]; then
    cp "$BUILD_DIR/ziro-rootfs-$TARGET_ARCH.tar.gz" "$ISO_STAGING/ziro/rootfs.tar.gz"
fi

# GRUB configuration for UEFI & BIOS (SeaBIOS, OVMF, VMware, VirtualBox, Proxmox)
cat > "$ISO_STAGING/boot/grub/grub.cfg" << EOF
serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1
terminal_input --append serial console
terminal_output --append serial console

set default=0
set timeout=5

menuentry "Ziro-OS Live Container Host & Installer" {
    linux /boot/vmlinuz console=ttyS0,115200 console=tty0 rdinit=/init quiet
    initrd /boot/initramfs.cpio.gz
}

menuentry "Ziro-OS Live (Serial Console)" {
    linux /boot/vmlinuz console=tty0 console=ttyS0,115200 rdinit=/init quiet
    initrd /boot/initramfs.cpio.gz
}

menuentry "Ziro-OS Automated Terminal Installer" {
    linux /boot/vmlinuz console=ttyS0,115200 console=tty0 rdinit=/init ziro.autoinstall quiet
    initrd /boot/initramfs.cpio.gz
}

menuentry "Ziro-OS (Recovery Shell)" {
    linux /boot/vmlinuz console=ttyS0,115200 console=tty0 rdinit=/bin/sh
    initrd /boot/initramfs.cpio.gz
}
EOF

# Determine bootloader packages based on architecture
if [ "$TARGET_ARCH" = "x86_64" ]; then
    GRUB_PACKAGES="grub-bios grub-efi"
else
    GRUB_PACKAGES="grub-efi"
fi

HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

echo "Building true hybrid BIOS + UEFI ISO for $TARGET_ARCH with grub-mkrescue..."
docker run --rm \
    -v "$ISO_STAGING:/iso" \
    -v "$BUILD_DIR:/out" \
    -e TARGET_ARCH="$TARGET_ARCH" \
    -e GRUB_PACKAGES="$GRUB_PACKAGES" \
    -e HOST_UID="$HOST_UID" \
    -e HOST_GID="$HOST_GID" \
    alpine:latest sh -c '
        set -e
        echo "Installing xorriso, mtools, and bootloader tools (${GRUB_PACKAGES})..."
        apk add --no-cache xorriso mtools ${GRUB_PACKAGES} >/dev/null 2>&1
        echo "Generating hybrid bootable ISO image with El Torito BIOS + UEFI catalogs..."
        grub-mkrescue -o "/out/ziro-os-${TARGET_ARCH}.iso" /iso 2>&1
        chown "${HOST_UID}:${HOST_GID}" "/out/ziro-os-${TARGET_ARCH}.iso"
    '

ISO_SIZE=$(du -h "$OUTPUT_ISO" | cut -f1)
echo "=================================================="
echo "✅ Bootable Hybrid ISO generated successfully!"
echo " Output: $OUTPUT_ISO ($ISO_SIZE)"
echo " Usable in: Proxmox (SeaBIOS & OVMF), VMware, VirtualBox, Bare Metal"
echo "=================================================="
