#!/bin/sh
# gosu USER[:GROUP] COMMAND [ARG]...: run COMMAND as USER, as gosu does, with util-linux's setpriv.
#
# The official PostgreSQL image ships gosu built with an old Go release (Trivy reports Go standard
# library CVEs in it, such as CVE-2025-68121 in crypto/tls, which gosu never uses). The Ziro image
# replaces the binary with this script so the image carries no vulnerable binary; the Ziro entry
# script and the official docker-entrypoint.sh both call it the same way.
set -eu
if [ "$#" -lt 2 ]; then
	echo "usage: gosu user-spec command [args]" >&2
	exit 1
fi
spec=$1
shift
user=${spec%%:*}
home=$(getent passwd "$user" | cut -d: -f6)
case "$spec" in
*:*) set -- --regid "${spec#*:}" --clear-groups -- "$@" ;;
*) set -- --regid "$(id -g "$user")" --init-groups -- "$@" ;;
esac
HOME=${home:-/} exec setpriv --reuid "$user" "$@"
