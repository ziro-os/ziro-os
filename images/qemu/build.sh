#!/bin/bash
# Build QEMU image for Ziro-OS

set -e

# Detect kernel architecture and set path
TARGET_ARCH="${TARGET_ARCH:-$(uname -m)}"
if [ "$TARGET_ARCH" = "aarch64" ]; then
    TARGET_ARCH="arm64"
fi

KERNEL_IMAGE="../../kernel/bzImage-${TARGET_ARCH}"
# Fallback to generic name if arch-specific doesn't exist
if [ ! -f "$KERNEL_IMAGE" ]; then
    KERNEL_IMAGE="../../kernel/bzImage"
fi
ROOTFS_DIR="../../rootfs"
OUTPUT_DIR="./output"

mkdir -p "$OUTPUT_DIR"

echo "Building Ziro-OS QEMU image..."

# Check if kernel exists
if [ ! -f "$KERNEL_IMAGE" ]; then
    echo "Error: Kernel image not found at $KERNEL_IMAGE"
    echo "Run 'make kernel' first"
    exit 1
fi

# Check if rootfs exists
if [ ! -d "$ROOTFS_DIR" ]; then
    echo "Error: Root filesystem not found at $ROOTFS_DIR"
    echo "Run 'make rootfs' first"
    exit 1
fi

# Create initramfs from rootfs
echo "Creating initramfs..."
INITRAMFS_DIR="$OUTPUT_DIR/initramfs"
rm -rf "$INITRAMFS_DIR"
mkdir -p "$INITRAMFS_DIR"

# Copy rootfs to initramfs (preserve symlinks)
cp -a "$ROOTFS_DIR"/* "$INITRAMFS_DIR/"

# Ensure init is executable
chmod +x "$INITRAMFS_DIR/etc/init"

# Create device nodes
mkdir -p "$INITRAMFS_DIR/dev"
mknod "$INITRAMFS_DIR/dev/console" c 5 1 2>/dev/null || true
mknod "$INITRAMFS_DIR/dev/null" c 1 3 2>/dev/null || true
mknod "$INITRAMFS_DIR/dev/zero" c 1 5 2>/dev/null || true

# Create initramfs archive
cd "$INITRAMFS_DIR"
find . | cpio -o -H newc -R 0:0 | gzip > "../initramfs.cpio.gz"
cd - > /dev/null

echo "Initramfs created: $(du -h $OUTPUT_DIR/initramfs.cpio.gz | cut -f1)"

# Copy kernel for direct boot
cp "$KERNEL_IMAGE" "$OUTPUT_DIR/vmlinuz"

echo "QEMU image components ready:"
echo "  Kernel: $OUTPUT_DIR/vmlinuz"
echo "  Initramfs: $OUTPUT_DIR/initramfs.cpio.gz"
echo ""
echo "To boot with QEMU:"
echo "  qemu-system-x86_64 -kernel $OUTPUT_DIR/vmlinuz -initrd $OUTPUT_DIR/initramfs.cpio.gz -m 512M -nographic -append 'console=ttyS0 init=/etc/init'"
