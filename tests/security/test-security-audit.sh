#!/bin/bash
# Ziro-OS Automated Security & Configuration Audit Test

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=================================================="
echo " Running Ziro-OS Security & Hardening Audit"
echo "=================================================="

FAILED=0

# 1. Check kernel security options
echo -n "Check 1: Kernel configs enable SECCOMP... "
if grep -q "CONFIG_SECCOMP=y" "$REPO_ROOT/kernel/configs/config-arm64" && \
   grep -q "CONFIG_SECCOMP=y" "$REPO_ROOT/kernel/configs/config-x86_64"; then
    echo "✅ PASSED"
else
    echo "❌ FAILED"
    FAILED=1
fi

echo -n "Check 2: Kernel configs enable User Namespaces... "
if grep -q "CONFIG_USER_NS=y" "$REPO_ROOT/kernel/configs/config-arm64" && \
   grep -q "CONFIG_USER_NS=y" "$REPO_ROOT/kernel/configs/config-x86_64"; then
    echo "✅ PASSED"
else
    echo "❌ FAILED"
    FAILED=1
fi

echo -n "Check 3: Hardened sysctl configurations... "
if grep -q "net.ipv4.ip_forward = 1" "$REPO_ROOT/rootfs/etc/sysctl.d/99-ziro.conf" && \
   grep -q "kernel.panic = 10" "$REPO_ROOT/rootfs/etc/sysctl.d/99-ziro.conf"; then
    echo "✅ PASSED"
else
    echo "❌ FAILED"
    FAILED=1
fi

# 2. Check no private keys or secrets committed
echo -n "Check 4: Tree scan for accidental private keys / secrets... "
SECRET_MATCHES=$(grep -rn "BEGIN RSA PRIVATE KEY" "$REPO_ROOT" --exclude-dir=".git" --exclude-dir="build" --exclude="test-security-audit.sh" || true)
if [ -z "$SECRET_MATCHES" ]; then
    echo "✅ PASSED"
else
    echo "❌ FAILED (Found private keys in repo)"
    FAILED=1
fi

# 3. Check for binary files in git-tracked rootfs
echo -n "Check 5: Rootfs skeleton purity (no binaries tracked)... "
BINARY_FILES=$(find "$REPO_ROOT/rootfs" -type f -perm +111 2>/dev/null | grep -v "\.sh" || true)
if [ -z "$BINARY_FILES" ]; then
    echo "✅ PASSED"
else
    echo "⚠️  Found executables in rootfs: $BINARY_FILES"
fi

echo "=================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "🎉 All security audit checks passed successfully!"
    exit 0
else
    echo "❌ Security audit detected failures."
    exit 1
fi
