# Ziro-OS Build System

.PHONY: all clean kernel rootfs image-qemu test-smoke

# Build targets
KERNEL_DIR = kernel
ROOTFS_DIR = rootfs
IMAGES_DIR = images
TOOLS_DIR = tools
PACKAGES_DIR = packages

# Default target
all: kernel rootfs tools

# Kernel build
kernel:
	@echo "Building kernel..."
	@cd $(KERNEL_DIR) && ./build.sh

# Root filesystem build  
rootfs:
	@echo "Building rootfs..."
	@$(MAKE) -C $(PACKAGES_DIR) all
	@$(MAKE) -C $(PACKAGES_DIR) install-to-rootfs

# Tools build
tools: bin/ziroctl

bin/ziroctl: $(TOOLS_DIR)/ziroctl/main.go
	@echo "Building tools..."
	@mkdir -p bin
	@go build -o bin/ziroctl ./$(TOOLS_DIR)/ziroctl/main.go

# QEMU image
image-qemu: kernel rootfs
	@echo "Building QEMU image..."
	@cd $(IMAGES_DIR)/qemu && ./build.sh

# Tests
test-smoke:
	@echo "Running smoke tests..."
	@cd tests/smoke && ./hello.sh

test-full: test-smoke
	@echo "Running full test suite..."
	# Add more comprehensive tests

# Clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(KERNEL_DIR)/build
	@rm -rf $(ROOTFS_DIR)/build
	@rm -rf $(IMAGES_DIR)/*/output
	@rm -f bin/*

# Package builds
$(PACKAGES_DIR)/%:
	@echo "Building package: $*"
	@cd $(PACKAGES_DIR) && ./build-package.sh $*

# Development helpers
dev-qemu: image-qemu
	@echo "Starting development QEMU instance..."
	@qemu-system-x86_64 \
		-m 512M \
		-drive file=images/qemu/output/ziro-os.qcow2,format=qcow2 \
		-netdev user,id=net0 \
		-device e1000,netdev=net0 \
		-nographic

help:
	@echo "Ziro-OS Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build kernel, rootfs, and tools"
	@echo "  kernel     - Build kernel only"
	@echo "  rootfs     - Build root filesystem"
	@echo "  tools      - Build CLI tools"
	@echo "  image-qemu - Build QEMU image"
	@echo "  test-smoke - Run smoke tests"
	@echo "  test-full  - Run full test suite"
	@echo "  dev-qemu   - Start development QEMU instance"
	@echo "  clean      - Clean build artifacts"
	@echo "  help       - Show this help"