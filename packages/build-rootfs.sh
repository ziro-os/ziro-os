#!/bin/bash
# Ziro-OS Robust Multi-Architecture Rootfs Builder
# Creates both minimal container base (< 10MB) and full container host OS initramfs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Architecture normalization
RAW_ARCH="${1:-$(uname -m)}"
case "$RAW_ARCH" in
    x86_64|amd64)
        TARGET_ARCH="x86_64"
        GOARCH="amd64"
        DOCKER_PLATFORM="linux/amd64"
        ALPINE_ARCH="x86_64"
        ;;
    arm64|aarch64)
        TARGET_ARCH="arm64"
        GOARCH="arm64"
        DOCKER_PLATFORM="linux/arm64"
        ALPINE_ARCH="aarch64"
        ;;
    *)
        echo "❌ Unsupported architecture: $RAW_ARCH"
        exit 1
        ;;
esac

echo "=================================================="
echo " Building Ziro-OS Rootfs"
echo " Target Architecture: $TARGET_ARCH ($GOARCH)"
echo " Platform: $DOCKER_PLATFORM"
echo "=================================================="

BUILD_DIR="$REPO_ROOT/build"
# Pinned Alpine release: kernel, modules and packages all come from one branch (reproducible builds)
ALPINE_IMAGE="${ALPINE_IMAGE:-alpine:3.24}"
DOWNLOAD_DIR="$BUILD_DIR/downloads"
ROOTFS_MINIMAL="$BUILD_DIR/rootfs-minimal-$TARGET_ARCH"
ROOTFS_FULL="$BUILD_DIR/rootfs-full-$TARGET_ARCH"

mkdir -p "$BUILD_DIR" "$DOWNLOAD_DIR"
if [ -d "$ROOTFS_MINIMAL" ] || [ -d "$ROOTFS_FULL" ]; then
    docker run --rm -v "$BUILD_DIR:/b" "$ALPINE_IMAGE" rm -rf "/b/rootfs-minimal-$TARGET_ARCH" "/b/rootfs-full-$TARGET_ARCH" 2>/dev/null || true
    rm -rf "$ROOTFS_MINIMAL" "$ROOTFS_FULL" 2>/dev/null || true
fi
mkdir -p "$ROOTFS_MINIMAL" "$ROOTFS_FULL"

# Helper for creating standard Linux directory layout
setup_layout() {
    local target="$1"
    mkdir -p "$target"/{bin,sbin,usr/bin,usr/sbin,lib,usr/lib}
    mkdir -p "$target"/{etc,var/log,var/lib/containerd,var/lib/containers,run,tmp}
    mkdir -p "$target"/{dev,proc,sys,mnt,opt/cni/bin,home,root}
    chmod 1777 "$target/tmp"
    chmod 0700 "$target/root"

    # Copy tracked etc configuration skeleton
    cp -r "$REPO_ROOT/rootfs/etc/"* "$target/etc/"
    chmod 0600 "$target/etc/shadow" 2>/dev/null || true
    chmod 0700 "$target/etc/crontabs" 2>/dev/null || true
    chmod 0600 "$target/etc/crontabs/root" 2>/dev/null || true
    
    # Copy tracked usr skeleton (e.g. udhcpc default script)
    if [ -d "$REPO_ROOT/rootfs/usr" ]; then
        mkdir -p "$target/usr"
        cp -r "$REPO_ROOT/rootfs/usr/"* "$target/usr/"
        chmod +x "$target/usr/share/udhcpc/default.script" 2>/dev/null || true
    fi
    mkdir -p "$target/lib/apk/db" "$target/etc/apk/keys"
    touch "$target/lib/apk/db/installed"
    touch "$target/etc/apk/world"
    local apk_arch="x86_64"
    if [ "$TARGET_ARCH" = "arm64" ] || [ "$TARGET_ARCH" = "aarch64" ]; then
        apk_arch="aarch64"
    fi
    echo "$apk_arch" > "$target/etc/apk/arch"

    # Copy trusted Alpine signing keys and repository list
    docker run --rm --platform "$DOCKER_PLATFORM" -v "$target:/rootfs" "$ALPINE_IMAGE" sh -c '
        mkdir -p /rootfs/etc/apk/keys
        cp -r /etc/apk/keys/* /rootfs/etc/apk/keys/ 2>/dev/null || true
        if [ ! -f /rootfs/etc/apk/repositories ]; then
            cp /etc/apk/repositories /rootfs/etc/apk/repositories 2>/dev/null || true
        fi
    '

    # Ensure TLS certificates exist for HTTPS package downloads
    mkdir -p "$target/etc/ssl/certs"
    if [ ! -f "$target/etc/ssl/certs/ca-certificates.crt" ]; then
        docker run --rm --platform "$DOCKER_PLATFORM" "$ALPINE_IMAGE" cat /etc/ssl/certs/ca-certificates.crt > "$target/etc/ssl/certs/ca-certificates.crt" 2>/dev/null || true
    fi
    if [ -f "$target/etc/ssl/certs/ca-certificates.crt" ]; then
        (cd "$target/etc/ssl" && ln -sf certs/ca-certificates.crt cert.pem)
    fi

    # Update architecture in ziro-release
    sed -i.bak "s/ARCH=\".*\"/ARCH=\"$TARGET_ARCH\"/g" "$target/etc/ziro-release" 2>/dev/null || true
    rm -f "$target/etc/ziro-release.bak"
}

setup_layout "$ROOTFS_MINIMAL"
setup_layout "$ROOTFS_FULL"

echo "✓ Skeleton directories and configurations prepared"

# --- 1. Fetch & Install BusyBox ---
echo "--- [1/5] Installing BusyBox ($TARGET_ARCH) ---"
BUSYBOX_BIN="$DOWNLOAD_DIR/busybox-$TARGET_ARCH"
if [ ! -f "$BUSYBOX_BIN" ]; then
    echo "Extracting static BusyBox for $TARGET_ARCH via Docker Alpine..."
    HOST_UID=$(id -u)
    HOST_GID=$(id -g)
    docker run --rm --platform "$DOCKER_PLATFORM" -v "$DOWNLOAD_DIR:/out" "$ALPINE_IMAGE" sh -c \
        "apk add --no-cache busybox-static >/dev/null 2>&1 && (cp /bin/busybox.static /out/busybox-$TARGET_ARCH || cp /bin/busybox /out/busybox-$TARGET_ARCH) && chmod 755 /out/busybox-$TARGET_ARCH && chown $HOST_UID:$HOST_GID /out/busybox-$TARGET_ARCH 2>/dev/null || true"
    chmod +x "$BUSYBOX_BIN" 2>/dev/null || true
fi

install_busybox() {
    local target="$1"
    cp "$BUSYBOX_BIN" "$target/bin/busybox"
    chmod +x "$target/bin/busybox" 2>/dev/null || true
    # Create clean relative symlinks
    docker run --rm --platform "$DOCKER_PLATFORM" -v "$target:/rootfs" "$ALPINE_IMAGE" sh -c '
        cd /rootfs/bin
        for app in $(./busybox --list); do
            case "$app" in
                init|reboot|poweroff|halt|shutdown|busybox)
                    continue
                    ;;
                *)
                    ln -sf busybox "$app"
                    ;;
            esac
        done
        cd /rootfs/sbin
        # Note: init, reboot, poweroff, halt, shutdown are intentionally excluded here so they never point to or overwrite busybox!
        for app in ifconfig route sysctl ip insmod rmmod modprobe lsmod; do
            ln -sf ../bin/busybox "$app"
        done
        rm -f /rootfs/init /rootfs/sbin/init /rootfs/bin/init /rootfs/sbin/reboot /rootfs/sbin/poweroff /rootfs/sbin/halt /rootfs/sbin/shutdown
    '
}

install_busybox "$ROOTFS_MINIMAL"
install_busybox "$ROOTFS_FULL"
echo "✓ BusyBox utilities installed"

# --- 2. Build & Install ziroctl and ziropkg ---
echo "--- [2/6] Compiling ziroctl and ziropkg ($GOARCH) ---"
mkdir -p "$REPO_ROOT/bin"
ZIROCTL_BIN="$REPO_ROOT/bin/ziroctl-$TARGET_ARCH"
(
    cd "$REPO_ROOT/tools/ziroctl"
    CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" go build -ldflags="-s -w" -o "$ZIROCTL_BIN" .
)
cp "$ZIROCTL_BIN" "$ROOTFS_MINIMAL/usr/bin/ziroctl"
cp "$ZIROCTL_BIN" "$ROOTFS_MINIMAL/bin/ziroctl"
cp "$ZIROCTL_BIN" "$ROOTFS_FULL/usr/bin/ziroctl"
cp "$ZIROCTL_BIN" "$ROOTFS_FULL/bin/ziroctl"

ZIROPKG_BIN="$REPO_ROOT/bin/ziropkg-$TARGET_ARCH"
(
    cd "$REPO_ROOT/tools/ziropkg"
    CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" go build -ldflags="-s -w" -o "$ZIROPKG_BIN" .
)
cp "$ZIROPKG_BIN" "$ROOTFS_MINIMAL/usr/bin/ziropkg"
cp "$ZIROPKG_BIN" "$ROOTFS_MINIMAL/bin/ziropkg"
cp "$ZIROPKG_BIN" "$ROOTFS_FULL/usr/bin/ziropkg"
cp "$ZIROPKG_BIN" "$ROOTFS_FULL/bin/ziropkg"

# Fetch & install static apk backend
APK_BIN="$DOWNLOAD_DIR/apk-$TARGET_ARCH"
if [ ! -f "$APK_BIN" ]; then
    echo "Extracting static APK package manager for $TARGET_ARCH..."
    HOST_UID=$(id -u)
    HOST_GID=$(id -g)
    docker run --rm --platform "$DOCKER_PLATFORM" -v "$DOWNLOAD_DIR:/out" "$ALPINE_IMAGE" sh -c \
        "apk add --no-cache apk-tools-static >/dev/null 2>&1 && cp /sbin/apk.static /out/apk-$TARGET_ARCH && chmod 755 /out/apk-$TARGET_ARCH && chown $HOST_UID:$HOST_GID /out/apk-$TARGET_ARCH 2>/dev/null || true"
    chmod +x "$APK_BIN" 2>/dev/null || true
fi
cp "$APK_BIN" "$ROOTFS_MINIMAL/sbin/apk"
cp "$APK_BIN" "$ROOTFS_MINIMAL/usr/bin/apk"
cp "$APK_BIN" "$ROOTFS_FULL/sbin/apk"
cp "$APK_BIN" "$ROOTFS_FULL/usr/bin/apk"
echo "✓ ziroctl, ziropkg, and apk package backend installed"

# --- 3. Build & Install ziro-init (PID 1) ---
echo "--- [3/5] Building ziro-init PID 1 supervisor ($TARGET_ARCH) ---"
INIT_BIN="$REPO_ROOT/init/ziro-init-$TARGET_ARCH"
# Always go through make: it rebuilds whenever ziro-init.c is newer than the binary,
# so a stale PID 1 (missing security fixes) can never ship.
make -C "$REPO_ROOT/init" TARGET_ARCH="$TARGET_ARCH"
rm -f "$ROOTFS_FULL/init" "$ROOTFS_FULL/sbin/init" "$ROOTFS_FULL/bin/init"
cp "$INIT_BIN" "$ROOTFS_FULL/init"
cp "$INIT_BIN" "$ROOTFS_FULL/sbin/init"
chmod +x "$ROOTFS_FULL/init" "$ROOTFS_FULL/sbin/init"

# Ensure busybox is untouched
if cmp -s "$ROOTFS_FULL/bin/busybox" "$INIT_BIN"; then
    echo "❌ FATAL: /bin/busybox was overwritten by ziro-init!"
    exit 1
fi

# For minimal rootfs (Docker base), /bin/sh is entrypoint, but provide init as option
rm -f "$ROOTFS_MINIMAL/sbin/ziro-init"
cp "$INIT_BIN" "$ROOTFS_MINIMAL/sbin/ziro-init"
chmod +x "$ROOTFS_MINIMAL/sbin/ziro-init"
echo "✓ ziro-init supervisor installed"

# --- 4. Package Minimal Docker Base Rootfs (< 10MB) ---
echo "--- [4/5] Packaging Minimal Docker Base Rootfs ---"
MINIMAL_TAR="$BUILD_DIR/ziro-rootfs-$TARGET_ARCH.tar.gz"
HOST_UID=$(id -u)
HOST_GID=$(id -g)
docker run --rm --platform "$DOCKER_PLATFORM" \
    -v "$ROOTFS_MINIMAL:/rootfs" \
    -v "$BUILD_DIR:/out" \
    -e TARGET_ARCH="$TARGET_ARCH" \
    -e HOST_UID="$HOST_UID" \
    -e HOST_GID="$HOST_GID" \
    "$ALPINE_IMAGE" sh -c '
        mkdir -p /rootfs/sbin /rootfs/bin /rootfs/usr/bin
        rm -f /rootfs/sbin/reboot /rootfs/sbin/poweroff /rootfs/sbin/halt /rootfs/sbin/shutdown
        rm -f /rootfs/bin/reboot /rootfs/bin/poweroff /rootfs/bin/halt /rootfs/bin/shutdown
        rm -f /rootfs/usr/bin/reboot /rootfs/usr/bin/poweroff /rootfs/usr/bin/shutdown

        cat > /rootfs/sbin/reboot << "SH_REBOOT"
#!/bin/sh
sync
kill -TERM 1 2>/dev/null || busybox reboot -f
SH_REBOOT
        cat > /rootfs/sbin/poweroff << "SH_POWEROFF"
#!/bin/sh
sync
kill -USR2 1 2>/dev/null || busybox poweroff -f
SH_POWEROFF
        cat > /rootfs/sbin/halt << "SH_HALT"
#!/bin/sh
sync
kill -USR1 1 2>/dev/null || busybox halt -f
SH_HALT
        cat > /rootfs/sbin/shutdown << "SH_SHUTDOWN"
#!/bin/sh
case "$1" in
    -r|--reboot|reboot) exec /sbin/reboot ;;
    *) exec /sbin/poweroff ;;
esac
SH_SHUTDOWN
        chmod 755 /rootfs/sbin/reboot /rootfs/sbin/poweroff /rootfs/sbin/halt /rootfs/sbin/shutdown
        cp -f /rootfs/sbin/reboot /rootfs/bin/reboot 2>/dev/null || true
        cp -f /rootfs/sbin/reboot /rootfs/usr/bin/reboot 2>/dev/null || true
        cp -f /rootfs/sbin/poweroff /rootfs/bin/poweroff 2>/dev/null || true
        cp -f /rootfs/sbin/poweroff /rootfs/usr/bin/poweroff 2>/dev/null || true
        cp -f /rootfs/sbin/halt /rootfs/bin/halt 2>/dev/null || true
        cp -f /rootfs/sbin/shutdown /rootfs/bin/shutdown 2>/dev/null || true
        cp -f /rootfs/sbin/shutdown /rootfs/usr/bin/shutdown 2>/dev/null || true

        # Validate that busybox is an authentic binary and not a script or symlink
        if [ ! -f /rootfs/bin/busybox ] || [ -L /rootfs/bin/busybox ] || [ $(wc -c < /rootfs/bin/busybox) -lt 100000 ]; then
            echo "❌ FATAL: /rootfs/bin/busybox is missing, truncated, or a symlink!"
            exit 1
        fi

        # Validate that /bin/sh executes correctly
        chroot /rootfs /bin/busybox sh -c "echo '\''✓ Minimal rootfs shell validated'\''"

        cd /rootfs
        tar --exclude="./dev/*" -czf "/out/ziro-rootfs-${TARGET_ARCH}.tar.gz" .
        chown "${HOST_UID}:${HOST_GID}" "/out/ziro-rootfs-${TARGET_ARCH}.tar.gz"
        chmod 644 "/out/ziro-rootfs-${TARGET_ARCH}.tar.gz"
        chmod -R a+rX /rootfs 2>/dev/null || true
    '
MINIMAL_SIZE=$(du -h "$MINIMAL_TAR" | cut -f1)
echo "✅ Minimal Base Rootfs archive: $MINIMAL_TAR ($MINIMAL_SIZE)"

# --- 5. Install Musl-Native Container Runtime, SSH, and System Utilities for Host OS ---
echo "--- [5/5] Installing musl-native containerd, nerdctl, runc, CNI plugins, and OpenSSH ---"
docker run --rm --platform "$DOCKER_PLATFORM" \
    -v "$ROOTFS_FULL:/rootfs" \
    -v "$BUILD_DIR:/out" \
    -e TARGET_ARCH="$TARGET_ARCH" \
    -e BUILD_FROM_SOURCE="${BUILD_FROM_SOURCE:-0}" \
    -e HOST_UID="$(id -u)" \
    -e HOST_GID="$(id -g)" \
    "$ALPINE_IMAGE" sh -c '
    # Kernel + modules always come from ONE source so their versions match:
    #   BUILD_FROM_SOURCE=1 -> kernel/build-kernel.sh output (build/kernel-<arch>/)
    #   default             -> Alpine linux-virt package
    apk add --no-cache kmod >/dev/null 2>&1
    mkdir -p /rootfs/lib/modules /rootfs/boot
    rm -rf /rootfs/lib/modules/*
    SRC="/out/kernel-${TARGET_ARCH}"
    if [ "${BUILD_FROM_SOURCE:-0}" = "1" ]; then
        if [ ! -f "$SRC/vmlinuz" ] || [ ! -f "$SRC/kernel.release" ]; then
            echo "BUILD_FROM_SOURCE=1 but $SRC has no kernel; run kernel/build-kernel.sh first" >&2
            exit 1
        fi
        echo "Using source-built kernel $(cat "$SRC/kernel.release")..."
        [ -d "$SRC/modroot/lib/modules" ] && cp -a "$SRC/modroot/lib/modules/." /rootfs/lib/modules/
        cp "$SRC/vmlinuz" /rootfs/boot/vmlinuz
        cp "$SRC/kernel.release" "/out/kernel-release-${TARGET_ARCH}"
    else
        echo "Installing kernel drivers & modules (linux-virt)..."
        apk add --no-cache linux-virt >/dev/null 2>&1
        cp -a /lib/modules/. /rootfs/lib/modules/
        cp /boot/vmlinuz-virt /rootfs/boot/vmlinuz
        ls /lib/modules > "/out/kernel-release-${TARGET_ARCH}"
    fi
    cp /rootfs/boot/vmlinuz "/out/vmlinuz-${TARGET_ARCH}"
    chown "${HOST_UID}:${HOST_GID}" "/out/vmlinuz-${TARGET_ARCH}" "/out/kernel-release-${TARGET_ARCH}"

    # Run depmod to index all kernel modules for fast, clean modprobe at boot
    for kver in /rootfs/lib/modules/*; do
        if [ -d "$kver" ]; then
            kname=$(basename "$kver")
            echo "Indexing kernel modules for $kname with depmod..."
            depmod -a -b /rootfs "$kname" 2>/dev/null || depmod -a "$kname" 2>/dev/null || true
        fi
    done

    mkdir -p /rootfs/etc/apk/keys
    cp -r /etc/apk/keys/* /rootfs/etc/apk/keys/ 2>/dev/null || true
    if [ ! -f /rootfs/etc/apk/repositories ]; then
        cp /etc/apk/repositories /rootfs/etc/apk/repositories 2>/dev/null || true
    fi

    GRUB_PKGS="grub-efi"
    if [ "$TARGET_ARCH" = "x86_64" ]; then
        GRUB_PKGS="grub-bios grub-efi"
    fi

    apk --root /rootfs --initdb \
        --keys-dir /etc/apk/keys \
        --repositories-file /etc/apk/repositories \
        --allow-untrusted \
        add --no-cache \
        ca-certificates containerd containerd-ctr nerdctl runc cni-plugins \
        iptables openssh-server openssh-client linux-pam \
        e2fsprogs dosfstools util-linux sfdisk parted curl kmod wireguard-tools nftables $GRUB_PKGS

    # Retain official keys and repositories inside rootfs for ziropkg
    cp -r /etc/apk/keys/* /rootfs/etc/apk/keys/ 2>/dev/null || true
    cp /etc/apk/repositories /rootfs/etc/apk/repositories 2>/dev/null || true

    mkdir -p /rootfs/opt/cni/bin /rootfs/var/empty /rootfs/run/sshd /rootfs/etc/ssh
    chmod 0700 /rootfs/var/empty
    if [ -d /rootfs/usr/libexec/cni ]; then
        cp -r /rootfs/usr/libexec/cni/* /rootfs/opt/cni/bin/ 2>/dev/null || true
    fi

    # Docker & Podman CLI compatibility symlinks
    ln -sf nerdctl /rootfs/usr/bin/docker
    ln -sf nerdctl /rootfs/usr/bin/podman
    if [ -f /rootfs/usr/bin/runc ]; then
        ln -sf /usr/bin/runc /rootfs/bin/runc
        ln -sf /usr/bin/runc /rootfs/sbin/runc
    fi

    # Route iptables through modern xtables-nft-multi for Linux kernel 6.x nftables compatibility
    NFT_TARGET=""
    if [ -f /rootfs/usr/sbin/xtables-nft-multi ]; then
        NFT_TARGET="/usr/sbin/xtables-nft-multi"
    elif [ -f /rootfs/sbin/xtables-nft-multi ]; then
        NFT_TARGET="/sbin/xtables-nft-multi"
    fi

    if [ -n "$NFT_TARGET" ]; then
        for p in /rootfs/sbin /rootfs/usr/sbin /rootfs/bin /rootfs/usr/bin; do
            mkdir -p "$p"
            ln -sf "$NFT_TARGET" "$p/iptables"
            ln -sf "$NFT_TARGET" "$p/iptables-save"
            ln -sf "$NFT_TARGET" "$p/iptables-restore"
            ln -sf "$NFT_TARGET" "$p/ip6tables"
            ln -sf "$NFT_TARGET" "$p/ip6tables-save"
            ln -sf "$NFT_TARGET" "$p/ip6tables-restore"
        done
    fi

    # Install dedicated reboot, poweroff, halt, and shutdown control scripts
    mkdir -p /rootfs/sbin /rootfs/bin /rootfs/usr/bin
    rm -f /rootfs/sbin/reboot /rootfs/sbin/poweroff /rootfs/sbin/halt /rootfs/sbin/shutdown
    rm -f /rootfs/bin/reboot /rootfs/bin/poweroff /rootfs/bin/halt /rootfs/bin/shutdown
    rm -f /rootfs/usr/bin/reboot /rootfs/usr/bin/poweroff /rootfs/usr/bin/shutdown

    cat > /rootfs/sbin/reboot << "SH_REBOOT"
#!/bin/sh
sync
kill -TERM 1 2>/dev/null || busybox reboot -f
SH_REBOOT
    cat > /rootfs/sbin/poweroff << "SH_POWEROFF"
#!/bin/sh
sync
kill -USR2 1 2>/dev/null || busybox poweroff -f
SH_POWEROFF
    cat > /rootfs/sbin/halt << "SH_HALT"
#!/bin/sh
sync
kill -USR1 1 2>/dev/null || busybox halt -f
SH_HALT
    cat > /rootfs/sbin/shutdown << "SH_SHUTDOWN"
#!/bin/sh
case "$1" in
    -r|--reboot|reboot) exec /sbin/reboot ;;
    *) exec /sbin/poweroff ;;
esac
SH_SHUTDOWN
    chmod 755 /rootfs/sbin/reboot /rootfs/sbin/poweroff /rootfs/sbin/halt /rootfs/sbin/shutdown
    cp -f /rootfs/sbin/reboot /rootfs/bin/reboot 2>/dev/null || true
    cp -f /rootfs/sbin/reboot /rootfs/usr/bin/reboot 2>/dev/null || true
    cp -f /rootfs/sbin/poweroff /rootfs/bin/poweroff 2>/dev/null || true
    cp -f /rootfs/sbin/poweroff /rootfs/usr/bin/poweroff 2>/dev/null || true
    cp -f /rootfs/sbin/halt /rootfs/bin/halt 2>/dev/null || true
    cp -f /rootfs/sbin/shutdown /rootfs/bin/shutdown 2>/dev/null || true
    cp -f /rootfs/sbin/shutdown /rootfs/usr/bin/shutdown 2>/dev/null || true

    # Validate that busybox is an authentic binary
    if [ ! -f /rootfs/bin/busybox ] || [ -L /rootfs/bin/busybox ] || [ $(wc -c < /rootfs/bin/busybox) -lt 100000 ]; then
        echo "❌ FATAL: /rootfs/bin/busybox is corrupt or overwritten in full rootfs!"
        exit 1
    fi

    # Fix permissions so non-root host user can manage files in rootfs
    chown -R "${HOST_UID}:${HOST_GID}" /rootfs 2>/dev/null || true
    chmod -R u+rwX /rootfs 2>/dev/null || true
'

# Re-affirm ziro-init and BusyBox after package additions
rm -f "$ROOTFS_FULL/init" "$ROOTFS_FULL/sbin/init"
cp "$INIT_BIN" "$ROOTFS_FULL/init"
cp "$INIT_BIN" "$ROOTFS_FULL/sbin/init"
chmod +x "$ROOTFS_FULL/init" "$ROOTFS_FULL/sbin/init"

# Install ziro-install script into rootfs
mkdir -p "$ROOTFS_FULL/usr/sbin" "$ROOTFS_FULL/bin"
cp "$REPO_ROOT/scripts/installer/ziro-install.sh" "$ROOTFS_FULL/usr/sbin/ziro-install"
cp "$REPO_ROOT/scripts/installer/ziro-install.sh" "$ROOTFS_FULL/bin/ziro-install"
chmod +x "$ROOTFS_FULL/usr/sbin/ziro-install" "$ROOTFS_FULL/bin/ziro-install"

if cmp -s "$ROOTFS_FULL/bin/busybox" "$INIT_BIN"; then
    echo "❌ FATAL: /bin/busybox was overwritten by ziro-init!"
    exit 1
fi
if [ ! -f "$ROOTFS_FULL/bin/busybox" ] || [ -L "$ROOTFS_FULL/bin/busybox" ] || [ $(wc -c < "$ROOTFS_FULL/bin/busybox") -lt 100000 ]; then
    echo "❌ FATAL: /bin/busybox in full rootfs is corrupted or overwritten!"
    exit 1
fi

# Package Full Host OS Initramfs via Docker container (runs as root, eliminating permission denied errors on /var/empty or lock files)
echo "Packaging Full Container OS Initramfs via Docker container..."
FULL_INITRAMFS="$BUILD_DIR/ziro-initramfs-$TARGET_ARCH.cpio.gz"
docker run --rm --platform "$DOCKER_PLATFORM" \
    -v "$ROOTFS_FULL:/rootfs" \
    -v "$BUILD_DIR:/out" \
    -e TARGET_ARCH="$TARGET_ARCH" \
    -e HOST_UID="$HOST_UID" \
    -e HOST_GID="$HOST_GID" \
    "$ALPINE_IMAGE" sh -c '
        rm -f /rootfs/lib/apk/db/lock /rootfs/var/run/*.pid /rootfs/run/*.pid
        for f in /rootfs/usr/lib/xtables/*.so; do
            [ -e "$f" ] || rm -f "$f"
        done
        # Create essential static devnodes inside initramfs (critical for early boot and switch_root)
        mkdir -p /rootfs/dev
        mknod -m 600 /rootfs/dev/console c 5 1 2>/dev/null || true
        mknod -m 666 /rootfs/dev/null c 1 3 2>/dev/null || true
        mknod -m 666 /rootfs/dev/zero c 1 5 2>/dev/null || true
        mknod -m 666 /rootfs/dev/tty c 5 0 2>/dev/null || true
        mknod -m 666 /rootfs/dev/tty0 c 4 0 2>/dev/null || true
        mknod -m 666 /rootfs/dev/tty1 c 4 1 2>/dev/null || true
        mknod -m 660 /rootfs/dev/ttyS0 c 4 64 2>/dev/null || true
        mknod -m 666 /rootfs/dev/urandom c 1 9 2>/dev/null || true

        cd /rootfs
        if command -v pigz >/dev/null 2>&1; then
            find . | cpio -o -H newc | pigz > "/out/ziro-initramfs-${TARGET_ARCH}.cpio.gz"
        else
            find . | cpio -o -H newc | gzip > "/out/ziro-initramfs-${TARGET_ARCH}.cpio.gz"
        fi
        chown "${HOST_UID}:${HOST_GID}" "/out/ziro-initramfs-${TARGET_ARCH}.cpio.gz"
        chmod 644 "/out/ziro-initramfs-${TARGET_ARCH}.cpio.gz"
        chmod -R a+rX /rootfs 2>/dev/null || true
    '
FULL_INITRAMFS="$BUILD_DIR/ziro-initramfs-$TARGET_ARCH.cpio.gz"
INITRAMFS_SIZE=$(du -h "$FULL_INITRAMFS" | cut -f1)
echo "✅ Full OS Initramfs:    $FULL_INITRAMFS ($INITRAMFS_SIZE)"

# Provide standard architecture alias symlinks for Docker buildx and release automation
if [ "$TARGET_ARCH" = "x86_64" ]; then
    ln -sf "ziro-rootfs-x86_64.tar.gz" "$BUILD_DIR/ziro-rootfs-amd64.tar.gz"
    ln -sf "ziro-initramfs-x86_64.cpio.gz" "$BUILD_DIR/ziro-initramfs-amd64.cpio.gz"
elif [ "$TARGET_ARCH" = "arm64" ]; then
    ln -sf "ziro-rootfs-arm64.tar.gz" "$BUILD_DIR/ziro-rootfs-aarch64.tar.gz"
    ln -sf "ziro-initramfs-arm64.cpio.gz" "$BUILD_DIR/ziro-initramfs-aarch64.cpio.gz"
fi

echo "=================================================="
echo " Rootfs build completed successfully for $TARGET_ARCH!"
echo " 1. Minimal Docker base: $MINIMAL_TAR ($MINIMAL_SIZE)"
echo " 2. Full OS Initramfs:   $FULL_INITRAMFS ($INITRAMFS_SIZE)"
echo "=================================================="
