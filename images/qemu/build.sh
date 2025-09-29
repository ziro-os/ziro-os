#!/bin/bash
# Build QEMU image for Ziro-OS

set -e

KERNEL_IMAGE="../kernel/bzImage"
ROOTFS_DIR="../rootfs"
OUTPUT_DIR="./output"

mkdir -p "$OUTPUT_DIR"

echo "Building QEMU image..."

# Create disk image
qemu-img create -f qcow2 "$OUTPUT_DIR/ziro-os.qcow2" 1G

# Create temporary mount point
MOUNT_POINT=$(mktemp -d)
LOOP_DEVICE=$(losetup -f)

# Format and mount
mkfs.ext4 "$OUTPUT_DIR/ziro-os.qcow2"
losetup "$LOOP_DEVICE" "$OUTPUT_DIR/ziro-os.qcow2"
mount "$LOOP_DEVICE" "$MOUNT_POINT"

# Copy rootfs
cp -r "$ROOTFS_DIR"/* "$MOUNT_POINT/"

# Install bootloader (simplified)
mkdir -p "$MOUNT_POINT/boot"
cp "$KERNEL_IMAGE" "$MOUNT_POINT/boot/vmlinuz"

# Cleanup
umount "$MOUNT_POINT"
losetup -d "$LOOP_DEVICE"
rmdir "$MOUNT_POINT"

echo "QEMU image built: $OUTPUT_DIR/ziro-os.qcow2"