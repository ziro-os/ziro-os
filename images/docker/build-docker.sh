#!/bin/bash
# Ziro-OS Docker Base Image Builder

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

HOST_ARCH=$(uname -m)
case "$HOST_ARCH" in
    x86_64|amd64)
        DEFAULT_TARGET="x86_64"
        ;;
    arm64|aarch64)
        DEFAULT_TARGET="arm64"
        ;;
    *)
        DEFAULT_TARGET="x86_64"
        ;;
esac

TARGET_ARCH="${1:-$DEFAULT_TARGET}"
case "$TARGET_ARCH" in
    x86_64|amd64)
        BUILD_ARCH="amd64"
        TARGET_ARCH="x86_64"
        ;;
    arm64|aarch64)
        BUILD_ARCH="arm64"
        TARGET_ARCH="arm64"
        ;;
esac

TAG="${IMAGE_TAG:-ziro-os:latest}"

echo "=================================================="
echo " Building Ziro-OS Docker Base Image"
echo " Architecture: $BUILD_ARCH ($TARGET_ARCH)"
echo " Image Tag:    $TAG"
echo "=================================================="

# Ensure rootfs archive exists
ROOTFS_TAR="$REPO_ROOT/build/ziro-rootfs-$TARGET_ARCH.tar.gz"
if [ ! -f "$ROOTFS_TAR" ]; then
    echo "Rootfs archive not found: $ROOTFS_TAR"
    echo "Running packages/build-rootfs.sh $TARGET_ARCH..."
    "$REPO_ROOT/packages/build-rootfs.sh" "$TARGET_ARCH"
fi

# Build local Docker image
echo "Building Docker container image $TAG..."
docker build \
    --platform "linux/$BUILD_ARCH" \
    --build-arg "TARGETARCH=$TARGET_ARCH" \
    -t "$TAG" \
    -f "$REPO_ROOT/images/docker/Dockerfile" \
    "$REPO_ROOT"

echo "=================================================="
echo " Validating Ziro-OS Container Image"
echo "=================================================="

echo "1. Testing Shell Execution:"
docker run --rm "$TAG" /bin/sh -c "echo '✅ Ziro-OS container running successfully!'"

echo "2. Testing ziroctl Version:"
docker run --rm "$TAG" ziroctl version

echo "3. Testing /etc/os-release:"
docker run --rm "$TAG" cat /etc/os-release

echo "=================================================="
echo " Image Details:"
docker images "$TAG"
echo "=================================================="
echo "✅ Ziro-OS Docker base image built and verified!"
