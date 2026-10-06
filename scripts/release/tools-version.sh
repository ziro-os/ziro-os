#!/bin/sh
# Decides the version of a tools release (ziroctl, ziropkg, zirocd). Tools versions are
# X.Y.Z (the build shipped with an OS release) or X.Y.Z.N, the Nth tools-only build of X.Y.Z
# (N >= 1; the bare X.Y.Z is N = 0, so every version has exactly one spelling). A build never
# needs a new OS version: it takes the next N of the newest tools version.
#
#   tools-version.sh next <VERSION> <tags>
#       The next build: the newest of the existing tools versions and VERSION, N + 1
#       (1.0.25.1 -> 1.0.25.2, 1.0.25 -> 1.0.25.1, nothing newer than VERSION 1.0.26 -> 1.0.26.1).
#   tools-version.sh resolve <ref-name> <input-version> <VERSION> <tags>
#       The version a workflow run publishes: the input if given, else the pushed tag
#       (tools/vX.Y.Z[.N] or an OS tag vX.Y.Z), else (a manual run without input) `next`.
#       Fails unless the version is canonical and newer than every existing tools version:
#       clients take the newest tag, so a lower one would never be installed.
#
# <tags> is a file (or - for stdin) with one tag per line, e.g. `git ls-remote --tags origin
# 'refs/tags/tools/v*'`; only tools/vX.Y.Z[.N] tags count, anything else is ignored.
set -eu

re='(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){2}(\.[1-9][0-9]*)?'

canonical() { printf '%s\n' "$1" | grep -Eq "^$re\$"; }

# stdin: versions. stdout: the same, oldest first (numeric on all four parts, missing N = 0).
sorted() {
    awk -F. '{ printf "%d %d %d %d %s\n", $1, $2, $3, ($4 == "" ? 0 : $4), $0 }' |
        sort -n -k1,1 -k2,2 -k3,3 -k4,4 | cut -d' ' -f5
}

# existing tools versions, one per line, from the tags file (or stdin)
existing() {
    grep -oE "(^|/)tools/v$re\$" "$1" | sed 's|.*tools/v||' | grep -E "^$re\$" || true
}

newest() { sorted | tail -1; }

next() {
    os=$1
    tags=$2
    printf '%s\n' "$os" | grep -Eq "^(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){2}\$" ||
        { echo "tools-version: VERSION '$os' is not a plain X.Y.Z" >&2; return 1; }
    top=$( { existing "$tags"; echo "$os"; } | newest)
    base=$(printf '%s\n' "$top" | cut -d. -f1-3)
    n=$(printf '%s\n' "$top" | cut -d. -f4)
    echo "$base.$(( ${n:-0} + 1 ))"
}

resolve() {
    ref=$1 input=$2 os=$3 tags=$4
    if [ -n "$input" ]; then
        v=${input#v}
    else
        case $ref in
            tools/v*) v=${ref#tools/v} ;;
            v[0-9]*) v=${ref#v} ;; # an OS release tag also publishes the matching tools release
            *) v=$(next "$os" "$tags") ;;
        esac
    fi
    canonical "$v" || { echo "tools-version: bad version '$v' (want X.Y.Z or X.Y.Z.N with N >= 1, no leading zeros)" >&2; return 1; }
    # the tag being built is itself among the existing ones when it triggered the run
    top=$(existing "$tags" | grep -vxF "$v" | newest || true)
    if [ -n "$top" ] && [ "$(printf '%s\n%s\n' "$top" "$v" | newest)" != "$v" ]; then
        echo "tools-version: $v is not newer than the existing tools release $top; clients install only the newest tag. Use a higher version, or leave the version empty for the next build." >&2
        return 1
    fi
    echo "$v"
}

# read the tags once: stdin cannot be read twice
case ${1:-} in
    next)
        [ $# -eq 3 ] || { echo "usage: tools-version.sh next <VERSION> <tags|->" >&2; exit 2; }
        t=$(mktemp); trap 'rm -f "$t"' EXIT
        if [ "$3" = "-" ]; then cat > "$t"; else cat "$3" > "$t"; fi
        next "$2" "$t" ;;
    resolve)
        [ $# -eq 5 ] || { echo "usage: tools-version.sh resolve <ref> <input> <VERSION> <tags|->" >&2; exit 2; }
        t=$(mktemp); trap 'rm -f "$t"' EXIT
        if [ "$5" = "-" ]; then cat > "$t"; else cat "$5" > "$t"; fi
        resolve "$2" "$3" "$4" "$t" ;;
    *) echo "usage: tools-version.sh next|resolve ..." >&2; exit 2 ;;
esac
