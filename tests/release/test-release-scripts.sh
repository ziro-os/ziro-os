#!/bin/sh
# Tests for scripts/release/*.sh: tools version numbering, the OS tag guard and the OS/tools
# split. Plain sh, no dependencies:  sh tests/release/test-release-scripts.sh
set -u
cd "$(dirname "$0")/../.." || exit 1
tv=scripts/release/tools-version.sh
fail=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

ok() { # ok <name> <want> <got>
    if [ "$2" = "$3" ]; then :; else printf 'FAIL %s: want [%s], got [%s]\n' "$1" "$2" "$3"; fail=1; fi
}
run() { sh "$@" 2>"$tmp/err"; }          # prints stdout; stderr kept in $tmp/err
rc() { sh "$@" >/dev/null 2>&1 && echo ok || echo fail; }

# ---- tools-version.sh next -------------------------------------------------------------
# Tags as `git ls-remote --tags` prints them, plus noise that must not count.
cat > "$tmp/tags" <<'T'
aaaa	refs/tags/tools/v1.0.21
aaaa	refs/tags/tools/v1.0.21.1
aaaa	refs/tags/tools/v1.0.21.9
aaaa	refs/tags/tools/v1.0.210
aaaa	refs/tags/tools/v1.0.21.0
aaaa	refs/tags/tools/v1.0.21-rc1
aaaa	refs/tags/tools/v01.0.99
aaaa	refs/tags/v1.0.99
aaaa	refs/tags/xtools/v1.0.98
T
ok next-skips-prefix-collision 1.0.210.1 "$(run $tv next 1.0.21 "$tmp/tags")"

cat > "$tmp/t2" <<'T'
tools/v1.0.21
tools/v1.0.21.1
tools/v1.0.21.9
T
ok next-after-9-is-10 1.0.21.10 "$(run $tv next 1.0.21 "$tmp/t2")"
printf 'tools/v1.0.21.10\ntools/v1.0.21.9\n' > "$tmp/t3"
ok next-numeric-not-lexical 1.0.21.11 "$(run $tv next 1.0.21 "$tmp/t3")"
printf 'tools/v1.0.21\n' > "$tmp/t4"
ok next-first-build-is-1 1.0.21.1 "$(run $tv next 1.0.21 "$tmp/t4")"
: > "$tmp/empty"
ok next-no-tags 1.0.21.1 "$(run $tv next 1.0.21 "$tmp/empty")"
# the tools line is ahead of VERSION (tools-only releases did not bump the OS): follow the tools line
printf 'tools/v1.0.25\ntools/v1.0.25.1\n' > "$tmp/t5"
ok next-follows-tools-line 1.0.25.2 "$(run $tv next 1.0.21 "$tmp/t5")"
# VERSION moved past every tools tag (new OS version, not yet published): its first build
ok next-new-os-version 1.0.26.1 "$(run $tv next 1.0.26 "$tmp/t5")"
ok next-stdin 1.0.25.2 "$(run $tv next 1.0.21 - < "$tmp/t5")"
ok next-bad-version fail "$(rc $tv next 1.0.21.1 "$tmp/t5")"

# ---- tools-version.sh resolve ----------------------------------------------------------
ok resolve-tag-push 1.0.25.2 "$(run $tv resolve tools/v1.0.25.2 '' 1.0.21 "$tmp/t5")"
# the pushed tag is itself among the remote tags: it must not block itself
printf 'tools/v1.0.25\ntools/v1.0.25.1\ntools/v1.0.25.2\n' > "$tmp/t6"
ok resolve-self-in-tags 1.0.25.2 "$(run $tv resolve tools/v1.0.25.2 '' 1.0.21 "$tmp/t6")"
ok resolve-input-wins 1.0.25.3 "$(run $tv resolve main v1.0.25.3 1.0.21 "$tmp/t6")"
ok resolve-os-tag 1.0.26 "$(run $tv resolve v1.0.26 '' 1.0.26 "$tmp/t5")"
ok resolve-dispatch-auto 1.0.25.3 "$(run $tv resolve refs/heads/main '' 1.0.21 "$tmp/t6")"
ok resolve-lower-refused fail "$(rc $tv resolve tools/v1.0.24.5 '' 1.0.21 "$tmp/t5")"
ok resolve-duplicate-of-other-refused fail "$(rc $tv resolve main 1.0.25 1.0.21 "$tmp/t5")"
ok resolve-zero-n-refused fail "$(rc $tv resolve tools/v1.0.26.0 '' 1.0.21 "$tmp/t5")"
ok resolve-leading-zero-refused fail "$(rc $tv resolve tools/v1.0.026 '' 1.0.21 "$tmp/t5")"
ok resolve-five-parts-refused fail "$(rc $tv resolve tools/v1.0.26.1.1 '' 1.0.21 "$tmp/t5")"
ok resolve-prerelease-refused fail "$(rc $tv resolve v1.0.26-rc1 '' 1.0.26 "$tmp/t5")"
ok resolve-garbage-refused fail "$(rc $tv resolve main latest 1.0.21 "$tmp/t5")"
ok resolve-first-ever 1.0.21 "$(run $tv resolve v1.0.21 '' 1.0.21 "$tmp/empty")"

# ---- tools-version.sh floor: an OS release must be higher than the tools line --------------
ok floor-follows-tools-line 1.0.25 "$(run $tv floor 1.0.22 "$tmp/t5")"
ok floor-version-ahead 1.0.26 "$(run $tv floor 1.0.26 "$tmp/t5")"
ok floor-no-tags 1.0.22 "$(run $tv floor 1.0.22 "$tmp/empty")"
# an OS tag below the tools line is refused, with the version to release instead
ok resolve-os-tag-below-line fail "$(rc $tv resolve v1.0.22 '' 1.0.22 "$tmp/t5")"
sh $tv resolve v1.0.22 '' 1.0.22 "$tmp/t5" 2>&1 | grep -q 'release.sh 1.0.26' || { echo "FAIL os-tag-hint: no 'release.sh 1.0.26' hint"; fail=1; }

# ---- release.sh bumps from the tools line and refuses what the tools workflow would reject ---
repo="$tmp/repo"
mkdir -p "$repo/scripts/release" && cp scripts/release.sh "$repo/scripts/" && cp $tv "$repo/scripts/release/"
(cd "$repo" && git init -q && git config user.email t@t && git config user.name t && echo 1.0.22 > VERSION &&
    git add . && git commit -qm init && git tag tools/v1.0.25 && git tag tools/v1.0.25.1)
rel() { (cd "$repo" && bash scripts/release.sh --dry-run "$@" 2>&1); }
ok release-patch-from-tools-line 1 "$(rel patch | grep -c 'Target Version:.*1\.0\.26')"
ok release-default-from-tools-line 1 "$(rel | grep -c 'Target Version:.*1\.0\.26')"
ok release-minor 1 "$(rel minor | grep -c 'Target Version:.*1\.1\.0')"
ok release-explicit-ok 1 "$(rel 1.0.27 | grep -c 'Target Version:.*1\.0\.27')"
ok release-below-line-refused 1 "$(rel 1.0.23 | grep -c 'cannot be released')"
ok release-rc-not-checked 1 "$(rel 1.0.23-rc1 | grep -c 'Target Version:.*1\.0\.23-rc1')"

# ---- check-tag.sh: only three-part OS tags start an OS release ---------------------------
ct=scripts/release/check-tag.sh
for t in v1.1.0 v1.0.21 v10.20.30 v1.1.0-rc1 v1.1.0-beta.2; do ok "tag-ok-$t" ok "$(rc $ct $t)"; done
for t in v1.1.0.3 v1.1.0.1 v1.1 v1 1.1.0 tools/v1.1.0 tools/v1.1.0.3 v1.1.0- v01.1.0 v1.1.0.3-rc1 v1.1.x; do ok "tag-refused-$t" fail "$(rc $ct $t)"; done

# ---- os-changed.sh: tools-only changes do not make an OS release -----------------------
oc=scripts/release/os-changed.sh
ok os-tools-only false "$(printf 'tools/ziroctl/cmd/update.go\nsdk/release/release.go\ndocs/upgrade.md\n' | sh $oc -)"
ok os-kernel true "$(printf 'tools/ziroctl/cmd/update.go\nkernel/build-kernel.sh\n' | sh $oc -)"
ok os-version-bump-only false "$(printf 'VERSION\nrootfs/etc/os-release\nimages/docker/Dockerfile\npublic/index.html\n' | sh $oc -)"
ok os-dev-tools true "$(printf 'tools/ziroctl/cmd/dev_kit.go\n' | sh $oc -)"

[ "$fail" = 0 ] && echo "release scripts: all tests passed"
exit "$fail"
