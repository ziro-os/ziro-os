#!/bin/bash
# Build minimal kernel for Ziro-OS

set -e

KERNEL_VERSION="6.6.3"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz"
BUILD_DIR="build"
CONFIG_FILE="config/ziro-minimal.config"

mkdir -p "$BUILD_DIR"

echo "Building Linux kernel $KERNEL_VERSION for Ziro-OS..."

# Check for required tools
for tool in make gcc bc bison flex libssl-dev libelf-dev; do
    if ! command -v $tool >/dev/null 2>&1 && ! dpkg -l | grep -q $tool; then
        echo "❌ Required tool/package not found: $tool"
        echo "Install with: sudo apt-get install build-essential bc bison flex libssl-dev libelf-dev"
        exit 1
    fi
done

# Download kernel source if not present
if [ ! -d "$BUILD_DIR/linux-$KERNEL_VERSION" ]; then
    echo "Downloading kernel source..."
    cd "$BUILD_DIR"
    
    # Check if we have wget or curl
    if command -v wget >/dev/null 2>&1; then
        wget "$KERNEL_URL"
    elif command -v curl >/dev/null 2>&1; then
        curl -L "$KERNEL_URL" -o "linux-${KERNEL_VERSION}.tar.xz"
    else
        echo "Error: Neither wget nor curl found. Please install one of them."
        exit 1
    fi
    
    echo "Extracting kernel source..."
    tar -xf "linux-${KERNEL_VERSION}.tar.xz"
    cd ..
fi

cd "$BUILD_DIR/linux-$KERNEL_VERSION"

# Copy our minimal config or create one
if [ -f "../../$CONFIG_FILE" ]; then
    echo "Applying Ziro-OS kernel configuration..."
    cp "../../$CONFIG_FILE" .config
else
    echo "Creating minimal kernel configuration..."
    make defconfig
    
    # Enable container features
    scripts/config --enable CONFIG_NAMESPACES
    scripts/config --enable CONFIG_UTS_NS
    scripts/config --enable CONFIG_IPC_NS
    scripts/config --enable CONFIG_USER_NS
    scripts/config --enable CONFIG_PID_NS
    scripts/config --enable CONFIG_NET_NS
    scripts/config --enable CONFIG_CGROUPS
    scripts/config --enable CONFIG_CGROUP_FREEZER
    scripts/config --enable CONFIG_CGROUP_DEVICE
    scripts/config --enable CONFIG_CGROUP_CPUACCT
    scripts/config --enable CONFIG_MEMCG
    scripts/config --enable CONFIG_SECCOMP
    scripts/config --enable CONFIG_SECCOMP_FILTER
    
    # Enable networking
    scripts/config --enable CONFIG_NET
    scripts/config --enable CONFIG_INET
    scripts/config --enable CONFIG_NETFILTER
    scripts/config --enable CONFIG_BRIDGE
    scripts/config --enable CONFIG_VETH
    
    # Enable filesystems
    scripts/config --enable CONFIG_EXT4_FS
    scripts/config --enable CONFIG_OVERLAY_FS
    scripts/config --enable CONFIG_TMPFS
    scripts/config --enable CONFIG_DEVTMPFS
    scripts/config --enable CONFIG_DEVTMPFS_MOUNT
    
    # Enable virtualization
    scripts/config --enable CONFIG_VIRTUALIZATION
    scripts/config --enable CONFIG_KVM
    scripts/config --enable CONFIG_KVM_INTEL
    scripts/config --enable CONFIG_KVM_AMD
    
    # Save config
    cp .config "../../$CONFIG_FILE"
fi

# Build kernel
echo "Compiling kernel (this may take a while)..."
make olddefconfig

# Use nproc if available, otherwise default to 4
NPROC=$(nproc 2>/dev/null || echo 4)
make -j$NPROC bzImage

# Copy output
cp arch/x86/boot/bzImage ../../bzImage
echo "Kernel built successfully: bzImage ($(du -h ../../bzImage | cut -f1))"

# Build essential modules
echo "Building essential kernel modules..."
make -j$NPROC modules

# Install essential modules
echo "Installing essential kernel modules..."
make INSTALL_MOD_PATH="../../modules" modules_install

echo "Kernel build complete!"
echo "  Kernel image: bzImage"
echo "  Modules: modules/"
echo "  Config saved: $CONFIG_FILE"