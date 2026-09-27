#!/bin/bash
# Test Ziro-OS QEMU image

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/output"

echo "=== Testing Ziro-OS QEMU Image ==="

# Check if files exist
if [ ! -f "$OUTPUT_DIR/vmlinuz" ]; then
    echo "❌ Kernel not found: $OUTPUT_DIR/vmlinuz"
    echo "Run 'make image-qemu' first"
    exit 1
fi

if [ ! -f "$OUTPUT_DIR/initramfs.cpio.gz" ]; then
    echo "❌ Initramfs not found: $OUTPUT_DIR/initramfs.cpio.gz"
    echo "Run 'make image-qemu' first"
    exit 1
fi

echo "✅ Found kernel: $(du -h $OUTPUT_DIR/vmlinuz | cut -f1)"
echo "✅ Found initramfs: $(du -h $OUTPUT_DIR/initramfs.cpio.gz | cut -f1)"

# Check kernel type
KERNEL_TYPE=$(file "$OUTPUT_DIR/vmlinuz" | cut -d: -f2)
echo "✅ Kernel type: $KERNEL_TYPE"

# Check initramfs contents
echo ""
echo "📦 Initramfs contents (container runtimes):"
gunzip -c "$OUTPUT_DIR/initramfs.cpio.gz" | cpio -t 2>/dev/null | grep -E "(containerd|runc|ctr)" | head -5

echo ""
echo "🚀 To test the QEMU image:"
echo ""

# Detect architecture for correct QEMU command
if echo "$KERNEL_TYPE" | grep -q "ARM64"; then
    echo "# ARM64 kernel detected - use qemu-system-aarch64:"
    echo "qemu-system-aarch64 \\"
    echo "  -machine virt \\"
    echo "  -cpu cortex-a57 \\"
    echo "  -kernel $OUTPUT_DIR/vmlinuz \\"
    echo "  -initrd $OUTPUT_DIR/initramfs.cpio.gz \\"
    echo "  -m 512M \\"
    echo "  -nographic \\"
    echo "  -append 'console=ttyAMA0 rdinit=/etc/init'"
elif echo "$KERNEL_TYPE" | grep -q "x86-64"; then
    echo "# x86_64 kernel detected - use qemu-system-x86_64:"
    echo "qemu-system-x86_64 \\"
    echo "  -kernel $OUTPUT_DIR/vmlinuz \\"
    echo "  -initrd $OUTPUT_DIR/initramfs.cpio.gz \\"
    echo "  -m 512M \\"
    echo "  -nographic \\"
    echo "  -append 'console=ttyS0 rdinit=/etc/init'"
else
    echo "# Generic QEMU command:"
    echo "qemu-system-x86_64 \\"
    echo "  -kernel $OUTPUT_DIR/vmlinuz \\"
    echo "  -initrd $OUTPUT_DIR/initramfs.cpio.gz \\"
    echo "  -m 512M \\"
    echo "  -nographic \\"
    echo "  -append 'console=ttyS0 rdinit=/etc/init'"
fi

echo ""
echo "💡 Tips:"
echo "  - Use Ctrl+A, X to exit QEMU"
echo "  - Add -netdev user,id=net0 -device e1000,netdev=net0 for networking"
echo "  - Add -enable-kvm for better performance (Linux hosts only)"

echo ""
echo "🎉 QEMU image test completed successfully!"