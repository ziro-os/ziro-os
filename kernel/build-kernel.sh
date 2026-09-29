#!/bin/bash
# Ziro-OS kernel builder. Two flavors:
#
#   KERNEL_FLAVOR=alpine (default)  Alpine linux-virt. Nothing to build here: packages/build-rootfs.sh
#                                   installs the kernel together with its matching modules.
#   KERNEL_FLAVOR=custom            Ziro kernel built from kernel.org sources: upstream defconfig
#                                   (broad hardware) + kernel/configs/ziro-*.config (containers,
#                                   security, every major cloud/hypervisor). Output: build/kernel-custom-<arch>/
#
# BUILD_FROM_SOURCE=1 is accepted as an alias for KERNEL_FLAVOR=custom.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

RAW_ARCH="${1:-$(uname -m)}"
case "$RAW_ARCH" in
    x86_64|amd64)
        TARGET_ARCH="x86_64"; KERNEL_ARCH="x86"; DOCKER_PLATFORM="linux/amd64"
        KERNEL_TARGET="bzImage"; KERNEL_OUT_SRC="arch/x86/boot/bzImage"
        ;;
    arm64|aarch64)
        TARGET_ARCH="arm64"; KERNEL_ARCH="arm64"; DOCKER_PLATFORM="linux/arm64"
        KERNEL_TARGET="vmlinuz.efi"; KERNEL_OUT_SRC="arch/arm64/boot/vmlinuz.efi"
        ;;
    *)
        echo "❌ Unsupported architecture: $RAW_ARCH"
        exit 1
        ;;
esac

KERNEL_FLAVOR="${KERNEL_FLAVOR:-alpine}"
[ "${BUILD_FROM_SOURCE:-0}" = "1" ] && KERNEL_FLAVOR="custom"

if [ "$KERNEL_FLAVOR" = "alpine" ]; then
    echo "KERNEL_FLAVOR=alpine: the linux-virt kernel and its modules are installed by packages/build-rootfs.sh."
    exit 0
fi
if [ "$KERNEL_FLAVOR" != "custom" ]; then
    echo "❌ Unknown KERNEL_FLAVOR '$KERNEL_FLAVOR' (use alpine or custom)"
    exit 1
fi

BUILD_DIR="$REPO_ROOT/build"
ALPINE_IMAGE="${ALPINE_IMAGE:-alpine:3.24}"
KERNEL_VER="${KERNEL_VERSION:-6.18.54}"   # longterm; same base as Alpine linux-virt
OUT="$BUILD_DIR/kernel-custom-$TARGET_ARCH"
CCACHE_DIR_HOST="$BUILD_DIR/ccache-$TARGET_ARCH"   # persisted by CI (actions/cache)
DL_DIR="$BUILD_DIR/dl"                             # kernel.org tarballs
mkdir -p "$OUT" "$CCACHE_DIR_HOST" "$DL_DIR"

# Skip the build when nothing that shapes the kernel changed (config fragments, this script,
# kernel version, toolchain image). Saves the full compile on every rootfs/ISO/CI rebuild.
STAMP=$(cat "$REPO_ROOT"/kernel/configs/*.config "$SCRIPT_DIR/build-kernel.sh" | { cat; echo "$KERNEL_VER $ALPINE_IMAGE $TARGET_ARCH"; } | sha256sum | cut -d' ' -f1)
if [ "${FORCE_KERNEL_BUILD:-0}" != "1" ] && [ -f "$OUT/vmlinuz" ] && [ -d "$OUT/modroot" ] && \
   [ "$(cat "$OUT/stamp" 2>/dev/null)" = "$STAMP" ]; then
    echo "✓ Custom kernel $(cat "$OUT/kernel.release") for $TARGET_ARCH is up to date (stamp ${STAMP:0:12}); skipping build."
    echo "  Set FORCE_KERNEL_BUILD=1 to rebuild."
    exit 0
fi
rm -f "$OUT/stamp"

echo "=================================================="
echo " Ziro custom kernel $KERNEL_VER for $TARGET_ARCH"
echo " Config:   ${KERNEL_ARCH} defconfig + ziro-common + ziro-$TARGET_ARCH"
echo " Output:   $OUT"
echo "=================================================="

docker run --rm --platform "$DOCKER_PLATFORM" \
    -v "$OUT:/build" \
    -v "$REPO_ROOT/kernel/configs:/configs:ro" \
    -v "$CCACHE_DIR_HOST:/ccache" -v "$DL_DIR:/dl" \
    -e CCACHE_DIR=/ccache -e CCACHE_MAXSIZE=2G -e CCACHE_COMPILERCHECK=content \
    -e KBUILD_BUILD_TIMESTAMP="ziro-$KERNEL_VER" -e KBUILD_BUILD_USER=ziro -e KBUILD_BUILD_HOST=ziro-build \
    -e KV="$KERNEL_VER" -e KARCH="$KERNEL_ARCH" -e TARCH="$TARGET_ARCH" \
    -e KTARGET="$KERNEL_TARGET" -e KOUT="$KERNEL_OUT_SRC" \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    "$ALPINE_IMAGE" sh -euc '
        apk add --no-cache build-base linux-headers bc bison flex openssl-dev elfutils-dev \
            perl python3 xz bash curl diffutils findutils kmod gzip openssl gawk ccache >/dev/null
        # Kernel scripts (e.g. x86 scripts/orc_hash.sh) need GNU awk; BusyBox awk rejects
        # regexes like "^struct orc_entry {$". /usr/local/bin is first in PATH.
        mkdir -p /usr/local/bin && ln -sf "$(command -v gawk)" /usr/local/bin/awk

        cd /build
        TARBALL="linux-$KV.tar.xz"
        if [ ! -d "linux-$KV" ]; then
            BASE="https://cdn.kernel.org/pub/linux/kernel/v${KV%%.*}.x"
            curl -fsSL "$BASE/sha256sums.asc" | grep " $TARBALL\$" > "/dl/$TARBALL.sha256"
            # Cached tarball is re-verified; a mismatch (partial/corrupt download) refetches.
            if ! (cd /dl && sha256sum -c "$TARBALL.sha256" >/dev/null 2>&1); then
                curl -fsSL -o "/dl/$TARBALL" "$BASE/$TARBALL"
                (cd /dl && sha256sum -c "$TARBALL.sha256")
            fi
            tar -xJf "/dl/$TARBALL"
        fi
        cd "linux-$KV"

        echo "Configuring: defconfig + Ziro fragments..."
        make -s ARCH=$KARCH CC="ccache gcc" defconfig
        ./scripts/kconfig/merge_config.sh -m -O . .config /configs/ziro-common.config "/configs/ziro-$TARCH.config" >/dev/null
        make -s ARCH=$KARCH CC="ccache gcc" olddefconfig

        # Every requested option must survive olddefconfig (renamed/unsatisfiable symbols fail the build).
        missing=""
        for frag in /configs/ziro-common.config "/configs/ziro-$TARCH.config"; do
            while IFS= read -r line; do
                case "$line" in
                    CONFIG_*=*)
                        sym=${line%%=*}; want=${line#*=}
                        got=$(grep -E "^$sym=" .config | cut -d= -f2- || true)
                        if [ "$want" = "y" ] && [ "$got" = "m" ]; then
                            echo "  note: $sym built as module (a dependency is modular)"
                        elif [ "$got" != "$want" ]; then
                            missing="$missing\n  $sym: want $want, got ${got:-unset}"
                        fi
                        ;;
                    "# CONFIG_"*" is not set")
                        sym=${line#"# "}; sym=${sym%% *}
                        if grep -qE "^$sym=[ym]" .config; then missing="$missing\n  $sym: want unset, got set"; fi
                        ;;
                esac
            done < "$frag"
        done
        if [ -n "$missing" ]; then
            printf "❌ Kernel config options dropped by olddefconfig:$missing\n" >&2
            exit 1
        fi
        echo "✓ All Ziro config options applied"

        echo "Compiling kernel + modules with $(nproc) jobs..."
        ccache -z >/dev/null
        make -s ARCH=$KARCH CC="ccache gcc" -j"$(nproc)" "$KTARGET" modules
        ccache -s | grep -Ei "hit|miss" || true

        rm -rf /build/modroot
        make -s ARCH=$KARCH CC="ccache gcc" INSTALL_MOD_PATH=/build/modroot INSTALL_MOD_STRIP=1 modules_install
        KREL=$(make -s ARCH=$KARCH CC="ccache gcc" kernelrelease)
        rm -f "/build/modroot/lib/modules/$KREL/build" "/build/modroot/lib/modules/$KREL/source"
        depmod -b /build/modroot "$KREL"

        cp "$KOUT" /build/vmlinuz
        cp .config /build/config
        echo "$KREL" > /build/kernel.release
        chown -R "$HOST_UID:$HOST_GID" /build/vmlinuz /build/config /build/kernel.release /build/modroot /ccache /dl
    '
echo "$STAMP" > "$OUT/stamp"

echo "=================================================="
echo "✅ Custom kernel $(cat "$OUT/kernel.release") ready: $OUT/vmlinuz ($(du -h "$OUT/vmlinuz" | cut -f1))"
echo "   modules: $(du -sh "$OUT/modroot" | cut -f1)   config: $OUT/config"
echo "   Next: KERNEL_FLAVOR=custom ./packages/build-rootfs.sh $TARGET_ARCH"
echo "=================================================="
