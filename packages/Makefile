# Package build system for Ziro-OS

.PHONY: all musl busybox containerd runc clean

PACKAGES_DIR = base
BUILD_DIR = build
ROOTFS_DIR = ../rootfs

all: musl busybox containerd runc

musl:
	@echo "Building musl libc..."
	@./build-package.sh musl

busybox: musl
	@echo "Building busybox..."
	@./build-package.sh busybox

containerd:
	@echo "Building containerd..."
	@./build-package.sh containerd

runc:
	@echo "Building runc..."
	@./build-package.sh runc

clean:
	@echo "Cleaning package builds..."
	@rm -rf $(BUILD_DIR)

install-to-rootfs:
	@echo "Installing packages to rootfs..."
	# Copy built binaries to rootfs structure
	@mkdir -p $(ROOTFS_DIR)/bin $(ROOTFS_DIR)/sbin $(ROOTFS_DIR)/usr/bin