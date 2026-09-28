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
KERNEL_FLAVOR="${KERNEL_FLAVOR:-alpine}"
[ "${BUILD_FROM_SOURCE:-0}" = "1" ] && KERNEL_FLAVOR="custom"
SUFFIX=""
[ "$KERNEL_FLAVOR" = "custom" ] && SUFFIX="-custom"
ISO_STAGING="$BUILD_DIR/iso-staging-$TARGET_ARCH$SUFFIX"
OUTPUT_ISO="$BUILD_DIR/ziro-os-$TARGET_ARCH$SUFFIX.iso"

mkdir -p "$BUILD_DIR"
rm -rf "$ISO_STAGING"
mkdir -p "$ISO_STAGING/boot/grub"

# Verify kernel
KERNEL_FILE="$BUILD_DIR/vmlinuz-$TARGET_ARCH$SUFFIX"
if [ ! -f "$KERNEL_FILE" ]; then
    echo "Kernel not found at $KERNEL_FILE. Building rootfs (provisions kernel + matching modules)..."
    "$REPO_ROOT/packages/build-rootfs.sh" "$TARGET_ARCH"
fi

# Verify initramfs
INITRAMFS_FILE="$BUILD_DIR/ziro-initramfs-$TARGET_ARCH$SUFFIX.cpio.gz"
if [ ! -f "$INITRAMFS_FILE" ]; then
    echo "Initramfs not found: $INITRAMFS_FILE"
    echo "Building rootfs first with: ./packages/build-rootfs.sh $TARGET_ARCH"
    "$REPO_ROOT/packages/build-rootfs.sh" "$TARGET_ARCH"
fi

# The kernel must match the modules packed in the initramfs, or every modprobe fails at boot.
KREL=$(cat "$BUILD_DIR/kernel-release-$TARGET_ARCH$SUFFIX" 2>/dev/null || true)
if [ -z "$KREL" ] || [ ! -d "$BUILD_DIR/rootfs-full-$TARGET_ARCH$SUFFIX/lib/modules/$KREL" ]; then
    echo "❌ Kernel/modules mismatch: kernel '${KREL:-unknown}' vs rootfs modules:" \
        "$(ls "$BUILD_DIR/rootfs-full-$TARGET_ARCH$SUFFIX/lib/modules" 2>/dev/null | tr '\n' ' ')"
    echo "   Rebuild both from one source: KERNEL_FLAVOR=$KERNEL_FLAVOR ./packages/build-rootfs.sh $TARGET_ARCH"
    exit 1
fi

echo "✓ Kernel:    $KERNEL_FILE ($KREL)"
echo "✓ Initramfs: $INITRAMFS_FILE"

# Copy boot artifacts
cp "$KERNEL_FILE" "$ISO_STAGING/boot/vmlinuz"
cp "$INITRAMFS_FILE" "$ISO_STAGING/boot/initramfs.cpio.gz"

# Bundle minimal rootfs archive on ISO if available for container extraction
mkdir -p "$ISO_STAGING/ziro"
if [ -f "$BUILD_DIR/ziro-rootfs-$TARGET_ARCH.tar.gz" ]; then
    cp "$BUILD_DIR/ziro-rootfs-$TARGET_ARCH.tar.gz" "$ISO_STAGING/ziro/rootfs.tar.gz"
fi

# GRUB configuration for UEFI & BIOS (SeaBIOS, OVMF, VMware, VirtualBox, Proxmox)
cat > "$ISO_STAGING/boot/grub/grub.cfg" << EOF
insmod part_gpt
insmod part_msdos
insmod ext2
insmod fat
insmod all_video
insmod gfxterm

serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1
terminal_input --append console serial
terminal_output --append console serial

set default=0
set timeout=5

menuentry "Ziro-OS Live Container Host & Installer" {
    linux /boot/vmlinuz console=ttyS0,115200 console=tty0 rdinit=/init
    initrd /boot/initramfs.cpio.gz
}

menuentry "Ziro-OS Live (Quiet Boot)" {
    linux /boot/vmlinuz console=ttyS0,115200 console=tty0 rdinit=/init quiet
    initrd /boot/initramfs.cpio.gz
}

menuentry "Ziro-OS Live (Serial Console Primary)" {
    linux /boot/vmlinuz console=tty0 console=ttyS0,115200 rdinit=/init
    initrd /boot/initramfs.cpio.gz
}

menuentry "Ziro-OS Automated Terminal Installer" {
    linux /boot/vmlinuz console=ttyS0,115200 console=tty0 rdinit=/init ziro.autoinstall
    initrd /boot/initramfs.cpio.gz
}

menuentry "Boot Installed Ziro-OS from Hard Drive (auto-detect)" {
    search --no-floppy --label --set=root ZIRO_ROOT
    linux /boot/vmlinuz root=LABEL=ZIRO_ROOT rootflags=rw console=ttyS0,115200 console=tty0
    initrd /boot/initramfs.cpio.gz
}

menuentry "Boot from Next Device / Local Disk (hd0)" {
    set root=(hd0)
    chainloader +1
}

menuentry "Ziro-OS (Recovery Shell)" {
    linux /boot/vmlinuz console=ttyS0,115200 console=tty0 rdinit=/init ziro.recovery
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
    -e SUFFIX="$SUFFIX" \
    -e GRUB_PACKAGES="$GRUB_PACKAGES" \
    -e HOST_UID="$HOST_UID" \
    -e HOST_GID="$HOST_GID" \
    "${ALPINE_IMAGE:-alpine:3.24}" sh -c '
        set -e
        echo "Installing xorriso, mtools, and bootloader tools (${GRUB_PACKAGES})..."
        apk add --no-cache xorriso mtools ${GRUB_PACKAGES} >/dev/null 2>&1
        echo "Generating hybrid bootable ISO image with El Torito BIOS + UEFI catalogs..."
        grub-mkrescue -o "/out/ziro-os-${TARGET_ARCH}${SUFFIX}.iso" /iso 2>&1
        chown "${HOST_UID}:${HOST_GID}" "/out/ziro-os-${TARGET_ARCH}${SUFFIX}.iso"
    '

ISO_SIZE=$(du -h "$OUTPUT_ISO" | cut -f1)
echo "=================================================="
echo "✅ Bootable Hybrid ISO generated successfully!"
echo " Output: $OUTPUT_ISO ($ISO_SIZE)"
echo " Usable in: Proxmox (SeaBIOS & OVMF), VMware, VirtualBox, Bare Metal"
echo "=================================================="
