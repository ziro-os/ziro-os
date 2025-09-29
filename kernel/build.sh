#!/bin/bash
# Build minimal kernel for Ziro-OS

set -e

KERNEL_VERSION="6.6.3"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz"
BUILD_DIR="build"
CONFIG_FILE="config/ziro-minimal.config"

mkdir -p "$BUILD_DIR"

echo "Building Linux kernel $KERNEL_VERSION for Ziro-OS..."

# Download kernel source if not present
if [ ! -d "$BUILD_DIR/linux-$KERNEL_VERSION" ]; then
    echo "Downloading kernel source..."
    cd "$BUILD_DIR"
    wget "$KERNEL_URL"
    tar -xf "linux-${KERNEL_VERSION}.tar.xz"
    cd ..
fi

cd "$BUILD_DIR/linux-$KERNEL_VERSION"

# Copy our minimal config
cp "../../$CONFIG_FILE" .config

# Build kernel
echo "Compiling kernel..."
make olddefconfig
make -j$(nproc) bzImage

# Copy output
cp arch/x86/boot/bzImage ../../bzImage

echo "Kernel built successfully: bzImage"