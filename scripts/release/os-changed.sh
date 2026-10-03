#!/bin/sh
# Prints "true" when the files changed between two refs need a new OS release (kernel, rootfs,
# images), "false" when only the tools stream (ziroctl, ziropkg: tools/vX) and docs changed.
# Reads `git diff --name-only <prev> <cur>`, or file names on stdin with "-".
#   usage: os-changed.sh <prev-ref> <cur-ref> | os-changed.sh -
set -eu
if [ "${1:-}" = "-" ]; then
    files=$(cat)
else
    files=$(git diff --name-only "${1:?usage: os-changed.sh <prev-ref> <cur-ref>}" "${2:?}")
fi

os=false
set -f # names are data, not globs
IFS='
'
for f in $files; do
    case "$f" in
        # Rewritten by scripts/release.sh on every bump.
        VERSION|rootfs/etc/os-release|images/docker/Dockerfile|public/index.html) ;;
        tools/ziroctl/cmd/version.go|tools/ziropkg/cmd/root.go) ;;
        # The kernel kit (kernel-devel, built by kernel-custom.yml) is coupled to these.
        tools/ziroctl/cmd/dev*.go) os=true ;;
        # Shipped by the tools stream (built-in modules are embedded in ziroctl), or not at all.
        tools/*|sdk/*|docs/*|community/*|*.md|.github/ISSUE_TEMPLATE/*) ;;
        *) os=true ;;
    esac
done
echo "$os"
