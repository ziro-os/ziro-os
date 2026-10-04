#!/bin/sh
# Signs <dir>/SHA256SUMS with the Ziro release key ($ZIRO_RELEASE_KEY, ed25519 PEM) into
# <dir>/SHA256SUMS.sig (base64), then verifies it against the public key ziroctl embeds, so a
# wrong or rotated secret fails the release instead of publishing something hosts reject.
set -eu
dir=${1:?usage: sign-sums.sh <dir>}
[ -n "${ZIRO_RELEASE_KEY:-}" ] || { echo "ZIRO_RELEASE_KEY is not set" >&2; exit 1; }
pub="$(cd "$(dirname "$0")/../.." && pwd)/sdk/release/release.pub"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
(umask 077; printf '%s\n' "$ZIRO_RELEASE_KEY" > "$tmp/key.pem")
openssl pkeyutl -sign -inkey "$tmp/key.pem" -rawin -in "$dir/SHA256SUMS" > "$tmp/sig.bin"
openssl pkeyutl -verify -pubin -inkey "$pub" -rawin -in "$dir/SHA256SUMS" -sigfile "$tmp/sig.bin"
base64 < "$tmp/sig.bin" | tr -d '\n' > "$dir/SHA256SUMS.sig"
