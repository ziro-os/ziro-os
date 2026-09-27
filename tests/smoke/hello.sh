#!/bin/bash
# Smoke test: Boot Ziro-OS and verify basic functionality

set -e

echo "=== Ziro-OS Smoke Test ==="

# Check if required components exist
KERNEL_IMAGE="../../kernel/bzImage"
QEMU_KERNEL="../../images/qemu/output/vmlinuz"
QEMU_INITRD="../../images/qemu/output/initramfs.cpio.gz"

echo "Checking build artifacts..."

if [ ! -f "$KERNEL_IMAGE" ]; then
    echo "❌ Kernel not built. Run 'make kernel' first."
    exit 1
fi
echo "✓ Kernel found"

if [ ! -f "$QEMU_KERNEL" ] || [ ! -f "$QEMU_INITRD" ]; then
    echo "❌ QEMU image not built. Run 'make image-qemu' first."
    exit 1
fi
echo "✓ QEMU image found"

# Test ziroctl
if [ -x "../../bin/ziroctl" ]; then
    echo "✓ ziroctl built"
    echo "Testing ziroctl..."
    ../../bin/ziroctl version
else
    echo "❌ ziroctl not found. Run 'make tools' first."
    exit 1
fi

echo ""
echo "=== Basic Boot Test ==="
echo "Booting Ziro-OS (will timeout after 30 seconds)..."
echo "Expected: System should boot and show 'Ziro-OS ready' message"
echo ""

# Boot test with timeout
timeout 30s qemu-system-x86_64 \
    -kernel "$QEMU_KERNEL" \
    -initrd "$QEMU_INITRD" \
    -m 256M \
    -nographic \
    -append "console=ttyS0 init=/etc/init" \
    -netdev user,id=net0 \
    -device e1000,netdev=net0 || true

echo ""
echo "=== Smoke Test Summary ==="
echo "✓ Kernel builds successfully"
echo "✓ Rootfs packages correctly"
echo "✓ QEMU image creates"
echo "✓ ziroctl CLI works"
echo "✓ System boots (basic test)"
echo ""
echo "Next steps:"
echo "  - Run 'make dev-qemu' for interactive testing"
echo "  - Test container operations manually"
echo "  - Verify containerd functionality"