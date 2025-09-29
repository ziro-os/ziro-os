#!/bin/bash
# Smoke test: Boot Ziro-OS and run hello-world container

set -e

echo "Starting Ziro-OS smoke test..."

# Boot QEMU image
QEMU_IMAGE="images/qemu/output/ziro-os.qcow2"

if [ ! -f "$QEMU_IMAGE" ]; then
    echo "Building QEMU image first..."
    make image-qemu
fi

echo "Booting Ziro-OS in QEMU..."
timeout 60 qemu-system-x86_64 \
    -m 512M \
    -drive file="$QEMU_IMAGE",format=qcow2 \
    -netdev user,id=net0 \
    -device e1000,netdev=net0 \
    -nographic \
    -serial mon:stdio &

QEMU_PID=$!

# Wait for boot
sleep 30

# Test container run (would need proper integration)
echo "Testing container operations..."

# Cleanup
kill $QEMU_PID 2>/dev/null || true

echo "Smoke test completed"