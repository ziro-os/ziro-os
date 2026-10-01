#!/bin/bash
# Ziro-OS Robust Multi-Architecture Rootfs Builder
# Creates both the minimal container base (~16MB) and the full container host OS initramfs (<300MB).

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
# Kernel flavor: custom (kernel/build-kernel.sh, the hardened default) or alpine (linux-virt,
# fallback). The minimal docker rootfs is flavor-independent. Host artifacts of the custom flavor
# keep their "-custom" suffix so hosts keep upgrading within their flavor.
KERNEL_FLAVOR="${KERNEL_FLAVOR:-custom}"
[ "${BUILD_FROM_SOURCE:-0}" = "1" ] && KERNEL_FLAVOR="custom"
case "$KERNEL_FLAVOR" in
    alpine) SUFFIX="" ;;
    custom) SUFFIX="-custom" ;;
    *) echo "❌ Unknown KERNEL_FLAVOR '$KERNEL_FLAVOR' (use alpine or custom)"; exit 1 ;;
esac
ROOTFS_FULL="$BUILD_DIR/rootfs-full-$TARGET_ARCH$SUFFIX"

# The rootfs is assembled on the host through a bind mount. On a case-insensitive filesystem
# (the macOS default) files that differ only in case collide, e.g. iptables' libxt_MARK.so and
# libxt_mark.so; the image then silently loses the MARK/DSCP/TTL... targets and container port
# publishing (CNI portmap) breaks. Refuse to build a broken image.
mkdir -p "$BUILD_DIR"
probe="$BUILD_DIR/.case-probe-$$"
rm -f "$probe" "$probe.X"; touch "$probe.x"
if [ -e "$probe.X" ] && [ "${ZIRO_ALLOW_CASE_INSENSITIVE:-0}" != "1" ]; then
    rm -f "$probe.x"
    echo "❌ $BUILD_DIR is on a case-insensitive filesystem: the image would lose iptables extensions." >&2
    echo "   Build from a case-sensitive volume, e.g. on macOS:" >&2
    echo "     hdiutil create -size 40g -fs 'Case-sensitive APFS' -volname ziro -type SPARSE ~/ziro.sparseimage" >&2
    echo "     hdiutil attach ~/ziro.sparseimage && git worktree add /Volumes/ziro/ziro-os" >&2
    echo "   (ZIRO_ALLOW_CASE_INSENSITIVE=1 builds anyway, with broken container port publishing.)" >&2
    exit 1
fi
rm -f "$probe.x"

mkdir -p "$BUILD_DIR" "$DOWNLOAD_DIR"
if [ -d "$ROOTFS_MINIMAL" ] || [ -d "$ROOTFS_FULL" ]; then
    docker run --rm --platform "$DOCKER_PLATFORM" -v "$BUILD_DIR:/b" "$ALPINE_IMAGE" rm -rf "/b/$(basename "$ROOTFS_MINIMAL")" "/b/$(basename "$ROOTFS_FULL")" 2>/dev/null || true
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
    
    # Copy tracked usr skeleton (DHCP uses busybox's udhcpc script from Alpine, configured
    # through /etc/udhcpc/udhcpc.conf: `ziroctl network dns` pins resolvers there).
    if [ -d "$REPO_ROOT/rootfs/usr" ]; then
        mkdir -p "$target/usr"
        cp -r "$REPO_ROOT/rootfs/usr/"* "$target/usr/"
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

# --- 4. Package Minimal Docker Base Rootfs (~16MB) ---
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

        # GNU tar is build-only; override member ownership without changing modes.
        mkdir -p "/out/apk-cache/$TARGET_ARCH" && apk add --cache-dir "/out/apk-cache/$TARGET_ARCH" tar >/dev/null || exit 1
        cd /rootfs
        tar --numeric-owner --owner=0 --group=0 --exclude="./dev/*" -czf "/out/ziro-rootfs-${TARGET_ARCH}.tar.gz" . || exit 1
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
    -e KERNEL_FLAVOR="$KERNEL_FLAVOR" \
    -e SUFFIX="$SUFFIX" \
    -e HOST_UID="$(id -u)" \
    -e HOST_GID="$(id -g)" \
    "$ALPINE_IMAGE" sh -c '
    # Kernel + modules always come from ONE source so their versions match:
    #   KERNEL_FLAVOR=custom -> kernel/build-kernel.sh output (build/kernel-custom-<arch>/)
    #   KERNEL_FLAVOR=alpine -> Alpine linux-virt package
    # Downloads are kept in build/apk-cache/<arch> (signatures are still verified on install).
    mkdir -p "/out/apk-cache/$TARGET_ARCH"
    apk add --cache-dir "/out/apk-cache/$TARGET_ARCH" kmod >/dev/null 2>&1
    mkdir -p /rootfs/lib/modules /rootfs/boot
    rm -rf /rootfs/lib/modules/*
    if [ "$KERNEL_FLAVOR" = "custom" ]; then
        SRC="/out/kernel-custom-${TARGET_ARCH}"
        if [ ! -f "$SRC/vmlinuz" ] || [ ! -f "$SRC/kernel.release" ]; then
            echo "KERNEL_FLAVOR=custom but $SRC has no kernel; run: KERNEL_FLAVOR=custom kernel/build-kernel.sh ${TARGET_ARCH}" >&2
            exit 1
        fi
        echo "Using Ziro custom kernel $(cat "$SRC/kernel.release")..."
        cp -a "$SRC/modroot/lib/modules/." /rootfs/lib/modules/
        cp "$SRC/vmlinuz" /rootfs/boot/vmlinuz
        cp "$SRC/kernel.release" "/out/kernel-release-${TARGET_ARCH}${SUFFIX}"
    else
        echo "Installing Alpine linux-virt kernel & modules..."
        apk add --cache-dir "/out/apk-cache/$TARGET_ARCH" linux-virt >/dev/null 2>&1
        cp -a /lib/modules/. /rootfs/lib/modules/
        cp /boot/vmlinuz-virt /rootfs/boot/vmlinuz
        ls /lib/modules > "/out/kernel-release-${TARGET_ARCH}${SUFFIX}"
    fi
    sed -i "/^KERNEL_FLAVOR=/d" /rootfs/etc/ziro-release
    echo "KERNEL_FLAVOR=\"$KERNEL_FLAVOR\"" >> /rootfs/etc/ziro-release
    cp /rootfs/boot/vmlinuz "/out/vmlinuz-${TARGET_ARCH}${SUFFIX}"
    chown "${HOST_UID}:${HOST_GID}" "/out/vmlinuz-${TARGET_ARCH}${SUFFIX}" "/out/kernel-release-${TARGET_ARCH}${SUFFIX}"

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

    # Signatures are verified against the Alpine keys (never --allow-untrusted). Transient mirror/DNS
    # errors are retried; a partial install must fail the build instead of shipping a broken host.
    ok=0
    for attempt in 1 2 3; do
        if apk --root /rootfs --initdb \
            --keys-dir /etc/apk/keys \
            --repositories-file /etc/apk/repositories \
            add --cache-dir "/out/apk-cache/$TARGET_ARCH" \
            ca-certificates containerd containerd-ctr nerdctl runc cni-plugins \
            iptables openssh-server openssh-client linux-pam \
            e2fsprogs e2fsprogs-extra dosfstools util-linux sfdisk parted curl kmod wireguard-tools nftables $GRUB_PKGS; then
            ok=1
            break
        fi
        echo "apk install failed (attempt $attempt/3); retrying in 15s..." >&2
        sleep 15
    done
    if [ "$ok" != 1 ]; then
        echo "FATAL: host packages failed to install" >&2
        exit 1
    fi
    for bin in usr/bin/containerd usr/bin/nerdctl usr/bin/runc usr/sbin/nft usr/sbin/sshd usr/bin/wg usr/sbin/iptables \
        usr/sbin/resize2fs; do
        if [ ! -x "/rootfs/$bin" ]; then
            echo "FATAL: /$bin missing from host rootfs" >&2
            exit 1
        fi
    done

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

# Alpine's DHCP CNI binary embeds an older x/net. Keep the CNI entry point and
# upstream plugin version, but rebuild against Ziro's checksum-locked overrides.
CNI_DHCP_BIN="$REPO_ROOT/bin/cni-dhcp-$TARGET_ARCH"
(
    cd "$REPO_ROOT/packages/cni-dhcp"
    CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" go build -mod=readonly -trimpath \
        -ldflags="-s -w -X github.com/containernetworking/plugins/pkg/utils/buildversion.BuildVersion=v1.9.1-ziro.1" \
        -o "$CNI_DHCP_BIN" github.com/containernetworking/plugins/plugins/ipam/dhcp
)
for destination in usr/libexec/cni/dhcp opt/cni/bin/dhcp; do
    cp "$CNI_DHCP_BIN" "$ROOTFS_FULL/$destination"
    chmod 0755 "$ROOTFS_FULL/$destination"
done

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

# Tiny boot initramfs for installed hosts (/boot/initramfs-boot.cpio.gz inside the OS image).
# It only has to find, fsck and switch to the root disk: ziro-init, static BusyBox, kmod's
# modprobe, e2fsck and the storage/filesystem modules. The installer and 'ziroctl upgrade' boot
# with it instead of the ~160 MB live image (faster GRUB load, far less RAM at boot).
echo "Packaging tiny boot initramfs for installed hosts..."
docker run --rm --platform "$DOCKER_PLATFORM" \
    -v "$ROOTFS_FULL:/rootfs" \
    -v "$BUILD_DIR:/out" \
    -e TARGET_ARCH="$TARGET_ARCH" \
    "$ALPINE_IMAGE" sh -c '
        set -eu
        mkdir -p "/out/apk-cache/$TARGET_ARCH"
        apk add --cache-dir "/out/apk-cache/$TARGET_ARCH" kmod >/dev/null
        T=/tmp/tiny
        mkdir -p $T/bin $T/sbin $T/lib $T/dev $T/proc $T/sys $T/sysroot $T/etc $T/run $T/tmp
        cp /rootfs/init $T/init
        cp /rootfs/sbin/init $T/sbin/init
        cp /rootfs/bin/busybox $T/bin/busybox
        for a in sh mount umount mknod mkdir cat ls find sort sed xargs blkid switch_root sleep mdev test; do
            ln -sf /bin/busybox "$T/bin/$a"
        done
        # Dynamic tools with the musl libraries they link against.
        LDSO=$(cd /rootfs/lib && ls ld-musl-*.so.1)
        cp -L "/rootfs/lib/$LDSO" "$T/lib/$LDSO"
        for b in /sbin/modprobe /sbin/e2fsck; do
            real=$(chroot /rootfs readlink -f "$b")
            mkdir -p "$T$(dirname "$real")" "$T$(dirname "$b")"
            cp -L "/rootfs$real" "$T$real"
            [ "$real" = "$b" ] || ln -sf "$real" "$T$b"
            chroot /rootfs "/lib/$LDSO" --list "$real" 2>/dev/null | awk "/=>/{print \$3}" | while read -r lib; do
                mkdir -p "$T$(dirname "$lib")"
                cp -L "/rootfs$lib" "$T$lib"
            done
        done
        # Storage + root filesystem modules and their dependencies (none for built-in drivers).
        KVER=$(ls /rootfs/lib/modules | head -n1)
        for m in virtio_pci virtio_mmio virtio_blk virtio_scsi nvme ahci ata_piix sd_mod \
                 xen_blkfront hv_storvsc vmw_pvscsi megaraid_sas mpt3sas mmc_block sdhci_pci \
                 usb_storage uas xhci_pci ehci_pci ext4 crc32c libcrc32c; do
            chroot /rootfs modprobe -S "$KVER" --show-depends "$m" 2>/dev/null || true
        done | awk "\$1==\"insmod\"{print \$2}" | sort -u | while read -r ko; do
            mkdir -p "$T$(dirname "$ko")"
            cp "/rootfs$ko" "$T$ko"
        done
        mkdir -p "$T/lib/modules/$KVER"
        for f in modules.order modules.builtin modules.builtin.modinfo; do
            [ -f "/rootfs/lib/modules/$KVER/$f" ] && cp "/rootfs/lib/modules/$KVER/$f" "$T/lib/modules/$KVER/"
        done
        depmod -b $T "$KVER"
        mknod -m 600 $T/dev/console c 5 1
        mknod -m 666 $T/dev/null c 1 3
        mkdir -p /rootfs/boot
        (cd $T && find . | cpio -o -H newc -R 0:0 2>/dev/null | gzip -9) > /rootfs/boot/initramfs-boot.cpio.gz
        chmod 644 /rootfs/boot/initramfs-boot.cpio.gz
        echo "✓ tiny boot initramfs: $(du -h /rootfs/boot/initramfs-boot.cpio.gz | cut -f1) ($(find $T/lib/modules -name "*.ko*" | wc -l) modules)"
    '

# Package Full Host OS Initramfs via Docker container (runs as root, eliminating permission denied errors on /var/empty or lock files)
echo "Packaging Full Container OS Initramfs via Docker container..."
FULL_INITRAMFS="$BUILD_DIR/ziro-initramfs-$TARGET_ARCH$SUFFIX.cpio.gz"
docker run --rm --platform "$DOCKER_PLATFORM" \
    -v "$ROOTFS_FULL:/rootfs" \
    -v "$BUILD_DIR:/out" \
    -e TARGET_ARCH="$TARGET_ARCH" \
    -e SUFFIX="$SUFFIX" \
    -e HOST_UID="$HOST_UID" \
    -e HOST_GID="$HOST_GID" \
    "$ALPINE_IMAGE" sh -c '
        set -eu
        set -o pipefail
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

        # Integrity baseline: SHA-256 of every executable, shared library and kernel module the
        # image ships. `ziroctl security integrity` compares IMA measurements against it.
        mkdir -p /rootfs/etc/ziro
        (cd /rootfs && find bin sbin usr/bin usr/sbin usr/libexec lib usr/lib opt/cni/bin -xdev -type f \
            \( -perm -u+x -o -name "*.so*" -o -name "*.ko*" \) -print0 2>/dev/null | sort -z | xargs -0 -r sha256sum \
            | sed "s#  #  /#") > /rootfs/etc/ziro/integrity.sha256
        chmod 0644 /rootfs/etc/ziro/integrity.sha256
        echo "✓ integrity baseline: $(wc -l < /rootfs/etc/ziro/integrity.sha256) files"

        mkdir -p "/out/apk-cache/$TARGET_ARCH"
        apk add --cache-dir "/out/apk-cache/$TARGET_ARCH" pigz >/dev/null 2>&1 || true   # multi-threaded gzip; falls back below
        cd /rootfs
        Z=gzip
        command -v pigz >/dev/null 2>&1 && Z=pigz
        # Never leave a truncated image behind: it would still boot, with files missing.
        # Only pack entries that stat: on a case-insensitive host bind mount (macOS) iptables
        # names like libxt_DSCP.so/libxt_dscp.so collide and one of each pair cannot be stat-ed.
        if ! { find . 2>/dev/null || true; } | while IFS= read -r p; do
                if [ -e "$p" ] || [ -L "$p" ]; then printf "%s\n" "$p"; fi
             done | cpio -o -H newc -R 0:0 | $Z > "/out/ziro-initramfs-${TARGET_ARCH}${SUFFIX}.cpio.gz"; then
            rm -f "/out/ziro-initramfs-${TARGET_ARCH}${SUFFIX}.cpio.gz"
            exit 1
        fi
        chown "${HOST_UID}:${HOST_GID}" "/out/ziro-initramfs-${TARGET_ARCH}${SUFFIX}.cpio.gz"
        chmod 644 "/out/ziro-initramfs-${TARGET_ARCH}${SUFFIX}.cpio.gz"
        chmod -R a+rX /rootfs 2>/dev/null || true
    '
FULL_INITRAMFS="$BUILD_DIR/ziro-initramfs-$TARGET_ARCH$SUFFIX.cpio.gz"
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
