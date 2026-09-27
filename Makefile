# Ziro-OS Centralized Build Orchestrator
# A cloud-native, ultra-lightweight operating system for container workloads.

.PHONY: all rootfs rootfs-all tools tools-all docker-image docker-multiarch kernel image-iso run-qemu test test-smoke clean help

HOST_ARCH := $(shell uname -m)
HOST_OS   := $(shell uname -s)
TARGET_ARCH ?= $(HOST_ARCH)

# Architecture normalization
ifeq ($(TARGET_ARCH),x86_64)
    ARCH_NORMALIZED = x86_64
    GOARCH = amd64
else ifeq ($(TARGET_ARCH),amd64)
    ARCH_NORMALIZED = x86_64
    GOARCH = amd64
else ifeq ($(TARGET_ARCH),arm64)
    ARCH_NORMALIZED = arm64
    GOARCH = arm64
else ifeq ($(TARGET_ARCH),aarch64)
    ARCH_NORMALIZED = arm64
    GOARCH = arm64
else
    ARCH_NORMALIZED = $(TARGET_ARCH)
    GOARCH = $(TARGET_ARCH)
endif

VERSION ?= 1.0.0
IMAGE_TAG ?= ziro-os:latest

all: tools rootfs docker-image
	@echo ""
	@echo "=================================================="
	@echo "🎉 Ziro-OS Build Complete for $(ARCH_NORMALIZED)"
	@echo "=================================================="

# --- CLI & Tooling ---
tools:
	@echo "Building ziroctl and ziropkg CLI for $(ARCH_NORMALIZED)..."
	@mkdir -p bin
	@cd tools/ziroctl && CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -ldflags="-s -w" -o ../../bin/ziroctl-$(ARCH_NORMALIZED) .
	@cp bin/ziroctl-$(ARCH_NORMALIZED) bin/ziroctl
	@cd tools/ziropkg && CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -ldflags="-s -w" -o ../../bin/ziropkg-$(ARCH_NORMALIZED) .
	@cp bin/ziropkg-$(ARCH_NORMALIZED) bin/ziropkg
	@echo "✅ ziroctl and ziropkg built at bin/"

tools-all:
	@echo "Building ziroctl and ziropkg for all architectures..."
	@mkdir -p bin
	@cd tools/ziroctl && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ../../bin/ziroctl-x86_64 .
	@cd tools/ziroctl && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o ../../bin/ziroctl-arm64 .
	@cd tools/ziropkg && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ../../bin/ziropkg-x86_64 .
	@cd tools/ziropkg && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o ../../bin/ziropkg-arm64 .
	@echo "✅ Built bin/ziroctl and bin/ziropkg for x86_64 and arm64"

# --- Rootfs & Userland ---
rootfs: tools
	@echo "Building rootfs for $(ARCH_NORMALIZED)..."
	@./packages/build-rootfs.sh $(ARCH_NORMALIZED)

rootfs-x86_64:
	@./packages/build-rootfs.sh x86_64

rootfs-arm64:
	@./packages/build-rootfs.sh arm64

rootfs-all: rootfs-x86_64 rootfs-arm64
	@echo "✅ Multi-arch rootfs built for x86_64 and arm64"

# --- Docker Base Image (Alpine-like) ---
docker-image: rootfs
	@echo "Building Docker base image ($(IMAGE_TAG))..."
	@./images/docker/build-docker.sh $(ARCH_NORMALIZED)

docker-multiarch: rootfs-all
	@echo "Building multi-architecture Docker image using buildx..."
	@docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-t $(IMAGE_TAG) \
		-f images/docker/Dockerfile \
		.
	@echo "✅ Multi-arch Docker image $(IMAGE_TAG) ready"

# --- Linux Kernel ---
kernel:
	@echo "Building Linux kernel for $(ARCH_NORMALIZED)..."
	@./kernel/build-kernel.sh $(ARCH_NORMALIZED)

# --- Virtualization & ISO ---
image-iso: rootfs
	@echo "Building bootable hybrid ISO..."
	@./images/iso/build-iso.sh $(ARCH_NORMALIZED)

run-qemu:
	@./images/qemu/run-qemu.sh $(ARCH_NORMALIZED)

# --- Verification & Tests ---
test: test-unit test-smoke

test-unit:
	@echo "Running ziroctl and ziropkg unit tests..."
	@cd tools/ziroctl && go test -v ./...
	@cd tools/ziropkg && go test -v ./...

test-smoke: docker-image
	@echo "Running container smoke test suite..."
	@./tests/smoke/test-docker-base.sh $(IMAGE_TAG)

# --- Cleanup ---
clean:
	@echo "Cleaning transient build artifacts..."
	@rm -rf build/
	@rm -f bin/ziroctl* bin/ziropkg*
	@echo "✅ Clean complete"

help:
	@echo "Ziro-OS Build Targets:"
	@echo "  all             - Build tools, rootfs, and Docker base image (default)"
	@echo "  tools           - Compile static ziroctl CLI for TARGET_ARCH"
	@echo "  tools-all       - Compile ziroctl for both x86_64 and arm64"
	@echo "  rootfs          - Build minimal rootfs (<10MB) and full initramfs"
	@echo "  rootfs-all      - Build rootfs for both x86_64 and arm64"
	@echo "  docker-image    - Build & verify local Docker base image (ziro-os:latest)"
	@echo "  docker-multiarch- Build multi-arch OCI image with Docker buildx"
	@echo "  kernel          - Build container-optimized Linux kernel"
	@echo "  image-iso       - Build bootable hybrid UEFI/BIOS ISO"
	@echo "  run-qemu        - Boot Ziro-OS microVM in QEMU"
	@echo "  test            - Run full test suite (unit tests + container smoke tests)"
	@echo "  clean           - Remove build artifacts"