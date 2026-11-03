#!/bin/sh
# Pins the published Ziro Postgres images in ziroctl (pgBackupImages in tools/ziroctl/cmd/pg_backup.go):
#   [OWNER=ziro-os] scripts/pg-image-digests.sh 16=sha256:<digest> 17=sha256:<digest> 18=sha256:<digest>
# The digests are in the summary of the "Postgres images" workflow run on main.
set -eu
owner=${OWNER:-ziro-os}
file="$(dirname "$0")/../tools/ziroctl/cmd/pg_backup.go"
for arg in "$@"; do
	v=${arg%%=*}
	d=${arg#*=}
	case "$v" in 16 | 17 | 18) ;; *) echo "unknown version $v" >&2; exit 2 ;; esac
	case "$d" in sha256:[0-9a-f]*) [ ${#d} -eq 71 ] || { echo "bad digest $d" >&2; exit 2; } ;; *) echo "bad digest $d" >&2; exit 2 ;; esac
	ref="ghcr.io/$owner/postgres:$v-pgbackrest@$d"
	sed -i "s|^\(\t\"$v\": \)\"[^\"]*\",|\1\"$ref\",|" "$file"
	grep -q "\"$v\": \"$ref\"" "$file" || { echo "could not pin $v in $file" >&2; exit 1; }
	echo "pinned $v: $ref"
done
