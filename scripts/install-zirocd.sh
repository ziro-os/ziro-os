#!/bin/sh
# Installs zirocd (Linux, macOS) from the signed tools release stream and starts its service.
#   curl -fsSL https://raw.githubusercontent.com/ziro-os/ziro-os/main/scripts/install-zirocd.sh | sh
#   ZIROCD_VERSION=1.0.21 sh install-zirocd.sh
# SHA256SUMS must carry the Ziro release signature (checked with openssl when it supports
# ed25519; the key below is sdk/release/release.pub) and the binary must match it.
set -eu
repo=ziro-os/ziro-os
dest=${ZIROCD_DEST:-/usr/local/bin}
pubkey='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA5X0B9KPGpkUbcOxlx8QV6W6p7dMV+Np+y7zspig9TWw=
-----END PUBLIC KEY-----'

case $(uname -s) in Linux) os=linux ;; Darwin) os=darwin ;; *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;; esac
case $(uname -m) in x86_64 | amd64) arch=amd64 ;; aarch64 | arm64) arch=arm64 ;; *) echo "unsupported CPU: $(uname -m)" >&2; exit 1 ;; esac
asset=zirocd-$os-$arch

version=${ZIROCD_VERSION:-}
if [ -z "$version" ]; then
	version=$(curl -fsSL "https://api.github.com/repos/$repo/git/matching-refs/tags/tools/v" |
		sed -n 's|.*"refs/tags/tools/v\([0-9]*\.[0-9]*\.[0-9]*\)".*|\1|p' |
		sort -t. -k1,1n -k2,2n -k3,3n | tail -1)
fi
case $version in [0-9]*.[0-9]*.[0-9]*) ;; *) echo "no zirocd release found" >&2; exit 1 ;; esac
base="https://github.com/$repo/releases/download/tools/v$version"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "Downloading zirocd $version ($os/$arch)..."
for f in "$asset" SHA256SUMS SHA256SUMS.sig; do curl -fsSLo "$tmp/$f" "$base/$f"; done

printf '%s\n' "$pubkey" > "$tmp/release.pub"
base64 -d < "$tmp/SHA256SUMS.sig" > "$tmp/sig.bin" 2>/dev/null || base64 -D < "$tmp/SHA256SUMS.sig" > "$tmp/sig.bin"
if openssl pkeyutl -verify -pubin -inkey "$tmp/release.pub" -rawin -in "$tmp/SHA256SUMS" -sigfile "$tmp/sig.bin" >/dev/null 2>&1; then
	echo "✓ release signature verified"
elif openssl pkeyutl -help 2>&1 | grep -q rawin; then
	echo "✗ SHA256SUMS signature does not verify: refusing to install" >&2
	exit 1
else
	echo "⚠ this openssl cannot check ed25519 signatures; relying on HTTPS + SHA-256 (zirocd verifies signatures on every update)" >&2
fi

want=$(awk -v f="$asset" '$2 == f || $2 == "*"f {print $1}' "$tmp/SHA256SUMS")
if command -v sha256sum >/dev/null; then got=$(sha256sum "$tmp/$asset" | cut -d' ' -f1); else got=$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1); fi
[ -n "$want" ] && [ "$want" = "$got" ] || { echo "✗ $asset does not match SHA256SUMS" >&2; exit 1; }
echo "✓ checksum verified"

sudo=
[ "$(id -u)" = 0 ] || sudo=sudo
$sudo mkdir -p "$dest"
$sudo install -m 0755 "$tmp/$asset" "$dest/zirocd"
$sudo "$dest/zirocd" service install
echo "Join a network:  sudo zirocd up --key zr1_..."
