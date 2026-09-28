# Makefile for Ziro-OS PID 1 Init
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c99
LDFLAGS ?= -static
TARGET_ARCH ?= $(shell uname -m)
ALPINE_IMAGE ?= alpine:3.24

ifeq ($(TARGET_ARCH),x86_64)
    DOCKER_PLATFORM = linux/amd64
else
    DOCKER_PLATFORM = linux/arm64
endif

.PHONY: all clean

all: ziro-init-$(TARGET_ARCH)
	@cp ziro-init-$(TARGET_ARCH) ziro-init

DOCKER_CMD := $(shell which docker 2>/dev/null)
MUSL_GCC := $(shell which musl-gcc 2>/dev/null)

ziro-init-$(TARGET_ARCH): ziro-init.c
	@echo "Building ziro-init for $(TARGET_ARCH)..."
ifneq ($(DOCKER_CMD),)
	@echo "Compiling statically with musl libc via Docker Alpine ($(DOCKER_PLATFORM))..."
	@docker run --rm --platform $(DOCKER_PLATFORM) -v $(shell pwd):/src -w /src $(ALPINE_IMAGE) sh -c \
		"apk add --no-cache gcc musl-dev binutils >/dev/null 2>&1 && gcc -static -s -O2 -Wall -Wextra -Werror ziro-init.c -o ziro-init-$(TARGET_ARCH) && chmod 755 ziro-init-$(TARGET_ARCH) && (chown $(shell id -u):$(shell id -g) ziro-init-$(TARGET_ARCH) 2>/dev/null || true)"
else ifneq ($(MUSL_GCC),)
	@echo "Compiling statically with musl-gcc..."
	$(MUSL_GCC) $(CFLAGS) -static -s ziro-init.c -o ziro-init-$(TARGET_ARCH)
else
	@echo "Compiling with host compiler (fallback)..."
	$(CC) $(CFLAGS) $(LDFLAGS) -s ziro-init.c -o ziro-init-$(TARGET_ARCH)
endif
	@chmod +x ziro-init-$(TARGET_ARCH) 2>/dev/null || true

clean:
	rm -f ziro-init ziro-init-*
