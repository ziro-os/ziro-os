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

# Test 5: Image size footprint (< 30MB)
echo -n "Test 5: Image size constraint (< 30MB)... "
SIZE_BYTES=$(docker inspect -f '{{.Size}}' "$IMAGE")
SIZE_MB=$((SIZE_BYTES / 1024 / 1024))
if [ "$SIZE_MB" -lt 30 ]; then
    echo "✅ PASSED (${SIZE_MB}MB)"
else
    echo "⚠️  WARNING: Image size is ${SIZE_MB}MB (exceeds 30MB target)"
fi

# Test 6: Package Manager CLI
echo -n "Test 6: ziropkg and ziroctl pkg CLI... "
OUTPUT_PKG=$(docker run --rm "$IMAGE" ziropkg version 2>&1)
OUTPUT_CTL=$(docker run --rm "$IMAGE" ziroctl pkg --help 2>&1)
if [[ "$OUTPUT_PKG" == *"ziropkg version"* ]] && [[ "$OUTPUT_CTL" == *"ziroctl pkg"* ]]; then
    echo "✅ PASSED"
else
    echo "❌ FAILED: Package manager CLI missing or broken"
    exit 1
fi

# Test 7: Package installation (curl)
echo -n "Test 7: Package installation via ziropkg (curl)... "
CURL_VER=$(docker run --rm "$IMAGE" /bin/sh -c "ziropkg install curl >/dev/null 2>&1 && curl --version | head -n 1")
if [[ "$CURL_VER" == *"curl"* ]]; then
    echo "✅ PASSED ($CURL_VER)"
else
    echo "❌ FAILED: Could not install or run curl"
    exit 1
fi

echo "=================================================="
echo "🎉 All Docker base container smoke tests passed!"
echo "=================================================="
