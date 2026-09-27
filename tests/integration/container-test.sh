#!/bin/bash
# Integration test for container functionality

set -e

echo "=== Ziro-OS Container Integration Test ==="

# Test containerd functionality
echo "Testing containerd..."

# Check if containerd is running
if ! pgrep containerd > /dev/null; then
    echo "❌ containerd is not running"
    exit 1
fi
echo "✓ containerd is running"

# Test ctr client
if ! command -v ctr > /dev/null; then
    echo "❌ ctr client not found"
    exit 1
fi
echo "✓ ctr client available"

# Test containerd API
if ! ctr version > /dev/null 2>&1; then
    echo "❌ containerd API not accessible"
    exit 1
fi
echo "✓ containerd API accessible"

# Pull a small test image
echo "Pulling hello-world image..."
if ! ctr images pull docker.io/library/hello-world:latest; then
    echo "❌ Failed to pull hello-world image"
    exit 1
fi
echo "✓ Image pulled successfully"

# List images
echo "Listing images..."
ctr images list

# Run hello-world container
echo "Running hello-world container..."
if ! ctr run --rm docker.io/library/hello-world:latest hello-test; then
    echo "❌ Failed to run container"
    exit 1
fi
echo "✓ Container ran successfully"

# Test ziroctl integration
echo "Testing ziroctl..."
if command -v ziroctl > /dev/null; then
    echo "✓ ziroctl available"
    ziroctl system status
    ziroctl container images
else
    echo "⚠️  ziroctl not in PATH"
fi

echo ""
echo "=== Container Test Summary ==="
echo "✓ containerd daemon running"
echo "✓ containerd API accessible"
echo "✓ Image pull functionality"
echo "✓ Container run functionality"
echo "✓ Basic container lifecycle"
echo ""
echo "Container runtime is fully functional!"