#!/bin/sh
# Accepts only a Ziro OS release tag: vX.Y.Z (optionally -prerelease), exactly three numeric
# parts. A four-part v1.1.0.3 is a tools build number, not an OS version: it must never start
# an OS release (kernels, images, and a `latest` release that every host's upgrade check reads).
# Tools-only builds are published as tools/vX.Y.Z.N by tools-release.yml.
#   usage: check-tag.sh <tag>
set -eu
tag=${1:?usage: check-tag.sh <tag>}
if printf '%s\n' "$tag" | grep -Eq '^v(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){2}(-[0-9A-Za-z][0-9A-Za-z.-]*)?$'; then
    exit 0
fi
echo "check-tag: '$tag' is not an OS release tag (want vX.Y.Z, e.g. v1.1.0)." >&2
echo "A tools-only build is published as tools/vX.Y.Z.N, never as vX.Y.Z.N." >&2
exit 1
