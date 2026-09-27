#!/bin/bash
# Size optimization script for Ziro-OS

set -e

ROOTFS_DIR="../rootfs"

echo "=== Ziro-OS Size Optimization ==="

# Strip debug symbols from binaries
echo "Stripping debug symbols..."
find "$ROOTFS_DIR/usr/bin" -type f -executable | while read -r binary; do
    if file "$binary" | grep -q "not stripped"; then
        echo "Stripping: $(basename "$binary")"
        strip "$binary" 2>/dev/null || true
    fi
done

# Remove unnecessary files
echo "Removing unnecessary files..."
find "$ROOTFS_DIR" -name "*.a" -delete 2>/dev/null || true
find "$ROOTFS_DIR" -name "*.la" -delete 2>/dev/null || true
find "$ROOTFS_DIR" -name "*.pc" -delete 2>/dev/null || true

# Compress binaries with UPX if available
if command -v upx > /dev/null 2>&1; then
    echo "Compressing binaries with UPX..."
    find "$ROOTFS_DIR/usr/bin" -type f -executable | while read -r binary; do
        if file "$binary" | grep -q "ELF"; then
            echo "Compressing: $(basename "$binary")"
            upx --best "$binary" 2>/dev/null || true
        fi
    done
fi

# Show size summary
echo ""
echo "=== Size Summary ==="
echo "Container runtime binaries:"
du -h "$ROOTFS_DIR/usr/bin"/* | sort -hr | head -10

echo ""
echo "Total rootfs size:"
du -sh "$ROOTFS_DIR"

echo ""
echo "CNI plugins:"
if [ -d "$ROOTFS_DIR/opt/cni/bin" ]; then
    du -h "$ROOTFS_DIR/opt/cni/bin"/*
fi