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
# CONFIG_ONLY=1 stops after configuring and verifying the fragments (a minute, no compile).
# ZIRO_MODULE_SIGNING_KEY (PEM: private key + certificate, from the CI secret) signs modules with
# the persistent Ziro key; it must match kernel/certs/ziro-modules.crt. Without it, the kernel
# build generates an ephemeral key, as before.

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

KERNEL_FLAVOR="${KERNEL_FLAVOR:-custom}"
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
# The persistent module key: written to a private temp file (never argv or env of the
# container) and checked against the committed certificate, so a wrong secret fails loudly.
KEYS_DIR=$(mktemp -d)
trap 'rm -rf "$KEYS_DIR"' EXIT
chmod 700 "$KEYS_DIR"
KEY_MODE=ephemeral
if [ -n "${ZIRO_MODULE_SIGNING_KEY:-}" ]; then
    ( umask 077; printf '%s\n' "$ZIRO_MODULE_SIGNING_KEY" > "$KEYS_DIR/signing_key.pem" )
    want=$(openssl x509 -in "$REPO_ROOT/kernel/certs/ziro-modules.crt" -noout -pubkey | sha256sum)
    got=$( (openssl x509 -in "$KEYS_DIR/signing_key.pem" -noout -pubkey 2>/dev/null || true) | sha256sum)
    keypub=$( (openssl pkey -in "$KEYS_DIR/signing_key.pem" -pubout 2>/dev/null || true) | sha256sum)
    if [ "$want" != "$got" ] || [ "$want" != "$keypub" ]; then
        echo "❌ ZIRO_MODULE_SIGNING_KEY doesn't match kernel/certs/ziro-modules.crt" >&2
        exit 1
    fi
    KEY_MODE=persistent
fi

STAMP=$(cat "$REPO_ROOT"/kernel/configs/*.config "$SCRIPT_DIR/build-kernel.sh" "$REPO_ROOT/kernel/certs/ziro-modules.crt" | { cat; echo "$KERNEL_VER $ALPINE_IMAGE $TARGET_ARCH"; } | sha256sum | cut -d' ' -f1)
# A build signed with the persistent key is reused even without the secret (later build steps
# don't carry it); an ephemeral-key build is replaced as soon as the persistent key is available.
BUILT_MODE=$(cat "$OUT/key-mode" 2>/dev/null || echo ephemeral)
# certMatches: the kernel in $OUT trusts (and signed its modules with) the committed Ziro key.
certMatches() {
    [ -f "$OUT/module-signing.crt" ] && [ "$(openssl x509 -in "$OUT/module-signing.crt" -noout -pubkey 2>/dev/null)" = \
        "$(openssl x509 -in "$REPO_ROOT/kernel/certs/ziro-modules.crt" -noout -pubkey)" ]
}
KEY_OK=1
[ "$BUILT_MODE" = persistent ] && ! certMatches && KEY_OK=0
[ "$KEY_MODE" = persistent ] && [ "$BUILT_MODE" != persistent ] && KEY_OK=0
if [ "${CONFIG_ONLY:-0}" != "1" ] && [ "${FORCE_KERNEL_BUILD:-0}" != "1" ] && [ -f "$OUT/vmlinuz" ] && [ -d "$OUT/modroot" ] && \
   [ "$KEY_OK" = 1 ] && [ "$(cat "$OUT/stamp" 2>/dev/null)" = "$STAMP" ]; then
    echo "✓ Custom kernel $(cat "$OUT/kernel.release") for $TARGET_ARCH is up to date (stamp ${STAMP:0:12}, $BUILT_MODE module key); skipping build."
    echo "  Set FORCE_KERNEL_BUILD=1 to rebuild."
    exit 0
fi
rm -f "$OUT/stamp" "$OUT/key-mode"

echo "=================================================="
echo " Ziro custom kernel $KERNEL_VER for $TARGET_ARCH"
echo " Config:   ${KERNEL_ARCH} defconfig + ziro-common + ziro-$TARGET_ARCH"
echo " Signing:  $KEY_MODE module key"
echo " Output:   $OUT"
echo "=================================================="

docker run --rm --platform "$DOCKER_PLATFORM" \
    -v "$OUT:/build" \
    -v "$REPO_ROOT/kernel/configs:/configs:ro" \
    -v "$CCACHE_DIR_HOST:/ccache" -v "$DL_DIR:/dl" -v "$KEYS_DIR:/keys:ro" \
    -e CONFIG_ONLY="${CONFIG_ONLY:-0}" \
    -e CCACHE_DIR=/ccache -e CCACHE_MAXSIZE=2G -e CCACHE_COMPILERCHECK=content \
    -e KBUILD_BUILD_TIMESTAMP="2026-01-01 00:00:00 UTC" -e KBUILD_BUILD_USER=ziro -e KBUILD_BUILD_HOST=ziro-build \
    -e KV="$KERNEL_VER" -e KARCH="$KERNEL_ARCH" -e TARCH="$TARGET_ARCH" \
    -e KTARGET="$KERNEL_TARGET" -e KOUT="$KERNEL_OUT_SRC" \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    "$ALPINE_IMAGE" sh -euc '
        apk add --no-cache build-base linux-headers bc bison flex openssl-dev elfutils-dev \
            perl python3 xz bash curl diffutils findutils kmod gzip openssl gawk ccache pahole zstd gnupg >/dev/null
        # Kernel scripts (e.g. x86 scripts/orc_hash.sh) need GNU awk; BusyBox awk rejects
        # regexes like "^struct orc_entry {$". /usr/local/bin is first in PATH.
        mkdir -p /usr/local/bin && ln -sf "$(command -v gawk)" /usr/local/bin/awk

        cd /build
        TARBALL="linux-$KV.tar.xz"
        if [ ! -d "linux-$KV" ]; then
            BASE="https://cdn.kernel.org/pub/linux/kernel/v${KV%%.*}.x"
            # sha256sums.asc is signed by the kernel.org checksum autosigner; pin its fingerprint.
            AUTOSIGNER=B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1
            export GNUPGHOME=$(mktemp -d)
            gpg -q --auto-key-locate clear,wkd --locate-keys autosigner@kernel.org >/dev/null 2>&1 || true
            gpg -q --list-keys --with-colons "$AUTOSIGNER" 2>/dev/null | grep -q "^fpr:::::::::$AUTOSIGNER:" || {
                echo "❌ could not fetch the kernel.org autosigner key $AUTOSIGNER" >&2; exit 1; }
            curl -fsSL -o /tmp/sha256sums.asc "$BASE/sha256sums.asc"
            gpg -q --status-fd 1 --verify /tmp/sha256sums.asc 2>/dev/null | grep -q "^\[GNUPG:\] VALIDSIG $AUTOSIGNER " || {
                echo "❌ sha256sums.asc signature is not from the kernel.org autosigner" >&2; exit 1; }
            gpg -q --decrypt /tmp/sha256sums.asc 2>/dev/null | grep " $TARBALL\$" > "/dl/$TARBALL.sha256"
            [ -s "/dl/$TARBALL.sha256" ] || { echo "❌ $TARBALL not listed in signed sha256sums" >&2; exit 1; }
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
        # Drivers needed before any module can load (root disk, console, initramfs): must be =y.
        CRITICAL=" VIRTIO_PCI VIRTIO_BLK SCSI_VIRTIO VIRTIO_NET BLK_DEV_NVME SATA_AHCI BLK_DEV_SD EXT4_FS HYPERV_STORAGE XEN_BLKDEV_FRONTEND DEVTMPFS DEVTMPFS_MOUNT EFI_STUB BLK_DEV_INITRD RD_GZIP RD_ZSTD SERIAL_8250_CONSOLE SERIAL_AMBA_PL011_CONSOLE "
        missing=""
        for frag in /configs/ziro-common.config "/configs/ziro-$TARCH.config"; do
            while IFS= read -r line; do
                case "$line" in
                    CONFIG_*=*)
                        sym=${line%%=*}; want=${line#*=}
                        got=$(grep -E "^$sym=" .config | cut -d= -f2- || true)
                        if [ "$want" = "y" ] && [ "$got" = "m" ]; then
                            case "$CRITICAL" in
                                *" ${sym#CONFIG_} "*) missing="$missing\n  $sym: boot-critical, must be built in (got m)" ;;
                                *) echo "  note: $sym built as module (a dependency is modular)" ;;
                            esac
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
        if [ "$CONFIG_ONLY" = "1" ]; then
            cp .config /build/config && chown "$HOST_UID:$HOST_GID" /build/config
            exit 0
        fi
        # Persistent module key (release builds): point MODULE_SIG_KEY at the mounted file. A key
        # copied to certs/signing_key.pem would be regenerated by certs/Makefile (x509.genkey is
        # newer), silently signing with an ephemeral key. Without the secret the kernel generates
        # an ephemeral key as usual.
        rm -f certs/signing_key.pem certs/signing_key.x509
        if [ -s /keys/signing_key.pem ]; then
            ./scripts/config --set-str MODULE_SIG_KEY /keys/signing_key.pem
            make -s ARCH=$KARCH CC="ccache gcc" olddefconfig
            grep -q "^CONFIG_MODULE_SIG_KEY=\"/keys/signing_key.pem\"" .config || { echo "❌ MODULE_SIG_KEY not applied" >&2; exit 1; }
        fi

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
        # Public half of whatever key signed the modules (kernel kit: verify out-of-tree builds).
        openssl x509 -inform DER -in certs/signing_key.x509 -out /build/module-signing.crt
        echo "$KREL" > /build/kernel.release
        chown -R "$HOST_UID:$HOST_GID" /build/vmlinuz /build/config /build/kernel.release /build/module-signing.crt /build/modroot /ccache /dl
    '
if [ "${CONFIG_ONLY:-0}" = "1" ]; then
    echo "✅ Config verified: $OUT/config"
    exit 0
fi
if [ "$KEY_MODE" = persistent ] && ! certMatches; then
    echo "❌ modules were not signed with the persistent Ziro key (kernel/certs/ziro-modules.crt)" >&2
    exit 1
fi
echo "$STAMP" > "$OUT/stamp"
echo "$KEY_MODE" > "$OUT/key-mode"

echo "=================================================="
echo "✅ Custom kernel $(cat "$OUT/kernel.release") ready: $OUT/vmlinuz ($(du -h "$OUT/vmlinuz" | cut -f1))"
echo "   modules: $(du -sh "$OUT/modroot" | cut -f1)   config: $OUT/config"
echo "   Next: KERNEL_FLAVOR=custom ./packages/build-rootfs.sh $TARGET_ARCH"
echo "=================================================="
