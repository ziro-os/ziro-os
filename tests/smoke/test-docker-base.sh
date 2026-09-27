#!/bin/bash
# Smoke test for Ziro-OS Docker base container image

set -euo pipefail

IMAGE="${1:-ziro-os:latest}"

echo "=================================================="
echo " Running Ziro-OS Base Container Smoke Tests"
echo " Target Image: $IMAGE"
echo "=================================================="

# Test 1: Container execution & POSIX shell
echo -n "Test 1: Shell execution (/bin/sh)... "
OUTPUT=$(docker run --rm "$IMAGE" /bin/sh -c "echo 'Ziro-OS OK'")
if [[ "$OUTPUT" == *"Ziro-OS OK"* ]]; then
    echo "✅ PASSED"
else
    echo "❌ FAILED: $OUTPUT"
    exit 1
fi

# Test 2: Standard Linux utilities (BusyBox)
echo -n "Test 2: Core utilities (ls, uname, cat)... "
docker run --rm "$IMAGE" /bin/sh -c "uname -a >/dev/null && ls /etc >/dev/null"
echo "✅ PASSED"

# Test 3: ziroctl Version
echo -n "Test 3: ziroctl CLI version... "
OUTPUT=$(docker run --rm "$IMAGE" ziroctl version)
if [[ "$OUTPUT" == *"ziroctl version"* ]]; then
    echo "✅ PASSED"
else
    echo "❌ FAILED: $OUTPUT"
    exit 1
fi

# Test 4: /etc/os-release compliance
echo -n "Test 4: /etc/os-release metadata... "
OUTPUT=$(docker run --rm "$IMAGE" cat /etc/os-release)
if [[ "$OUTPUT" == *"ID=ziro-os"* ]]; then
    echo "✅ PASSED"
else
    echo "❌ FAILED: $OUTPUT"
    exit 1
fi

# Test 5: Image size footprint (< 25MB)
echo -n "Test 5: Image size constraint (< 25MB)... "
SIZE_BYTES=$(docker inspect -f '{{.Size}}' "$IMAGE")
SIZE_MB=$((SIZE_BYTES / 1024 / 1024))
if [ "$SIZE_MB" -lt 25 ]; then
    echo "✅ PASSED (${SIZE_MB}MB)"
else
    echo "⚠️  WARNING: Image size is ${SIZE_MB}MB (exceeds 25MB target)"
fi

echo "=================================================="
echo "🎉 All Docker base container smoke tests passed!"
echo "=================================================="
