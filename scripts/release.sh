#!/usr/bin/env bash
# Ziro-OS Automated Version Bumping & Release Script
# Automatically calculates new semantic versions, updates build metadata,
# commits, tags, and pushes to remote to trigger GitHub Actions release workflows.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Color constants
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_usage() {
    cat <<EOF
Ziro-OS Release & Version Automation Utility

Usage:
  $(basename "$0") [OPTIONS] [COMMAND]

Commands:
  patch                  Bump patch version (e.g., 1.0.0 -> 1.0.1) [DEFAULT]
  minor                  Bump minor version (e.g., 1.0.0 -> 1.1.0)
  major                  Bump major version (e.g., 1.0.0 -> 2.0.0)
  <version>              Specify exact version (e.g., 1.2.0 or v1.2.0)
  current                Display current version and latest Git tag

Options:
  --dry-run              Preview changes without committing or tagging
  --no-push              Commit and tag locally, but do not push to remote
  --notes <message>      Add custom release notes message
  -h, --help             Display this help message

Examples:
  ./scripts/release.sh                 # Automatically bumps patch version (1.0.0 -> 1.0.1)
  ./scripts/release.sh minor           # Bumps minor version (1.0.0 -> 1.1.0)
  ./scripts/release.sh 1.2.0           # Sets explicit version 1.2.0
  ./scripts/release.sh --dry-run patch # Previews release without making git changes
EOF
}

DRY_RUN=false
PUSH_REMOTE=true
CUSTOM_NOTES=""
BUMP_TYPE="patch"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --no-push)
            PUSH_REMOTE=false
            shift
            ;;
        --notes)
            CUSTOM_NOTES="$2"
            shift 2
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        patch|minor|major|current)
            BUMP_TYPE="$1"
            shift
            ;;
        v[0-9]*|[0-9]*)
            BUMP_TYPE="$1"
            shift
            ;;
        *)
            echo -e "${RED}❌ Unknown argument: $1${NC}"
            print_usage
            exit 1
            ;;
    esac
done

cd "$REPO_ROOT"

# Determine Current Version
CURRENT_VERSION=""
if [ -f "$REPO_ROOT/VERSION" ]; then
    CURRENT_VERSION=$(tr -d ' \t\n\r' < "$REPO_ROOT/VERSION")
fi

if [ -z "$CURRENT_VERSION" ]; then
    LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
    if [ -n "$LATEST_TAG" ]; then
        CURRENT_VERSION="${LATEST_TAG#v}"
    else
        CURRENT_VERSION="1.0.0"
    fi
fi

# Clean current version (strip any leading v)
CURRENT_VERSION="${CURRENT_VERSION#v}"

# Handle 'current' command
if [ "$BUMP_TYPE" = "current" ]; then
    LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "None")
    COMMIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    echo "=================================================="
    echo " Ziro-OS Version Information"
    echo "=================================================="
    echo -e "Current Version: ${GREEN}${CURRENT_VERSION}${NC} (Tag: v${CURRENT_VERSION})"
    echo -e "Latest Git Tag:  ${CYAN}${LATEST_TAG}${NC}"
    echo -e "Head Commit:     ${YELLOW}${COMMIT_HASH}${NC}"
    exit 0
fi

# Parse SemVer components
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VERSION"
MAJOR="${MAJOR:-1}"
MINOR="${MINOR:-0}"
PATCH="${PATCH:-0}"
# Strip any pre-release suffixes from patch for arithmetic
PATCH_NUM="${PATCH%%-*}"

# Calculate Next Version
NEW_VERSION=""
case "$BUMP_TYPE" in
    patch)
        NEW_PATCH=$((PATCH_NUM + 1))
        NEW_VERSION="${MAJOR}.${MINOR}.${NEW_PATCH}"
        ;;
    minor)
        NEW_MINOR=$((MINOR + 1))
        NEW_VERSION="${MAJOR}.${NEW_MINOR}.0"
        ;;
    major)
        NEW_MAJOR=$((MAJOR + 1))
        NEW_VERSION="${NEW_MAJOR}.0.0"
        ;;
    *)
        # Explicit version string passed
        RAW_VER="${BUMP_TYPE#v}"
        if [[ ! "$RAW_VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
            echo -e "${RED}❌ Invalid semantic version format: '$BUMP_TYPE'. Expected format: X.Y.Z (e.g. 1.1.0)${NC}"
            exit 1
        fi
        NEW_VERSION="$RAW_VER"
        ;;
esac

TAG="v${NEW_VERSION}"
BUILD_DATE=$(date -u +"%Y-%m-%d")
BUILD_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")

echo "=================================================="
echo " 🚀 Ziro-OS Release Automation"
echo "=================================================="
echo -e "Current Version:  ${YELLOW}${CURRENT_VERSION}${NC} (v${CURRENT_VERSION})"
echo -e "Target Version:   ${GREEN}${NEW_VERSION}${NC} (${TAG})"
echo -e "Build Date:       ${CYAN}${BUILD_DATE}${NC} (${BUILD_TIMESTAMP})"
echo -e "Target Branch:    ${BLUE}${CURRENT_BRANCH}${NC}"
echo -e "Mode:             $([ "$DRY_RUN" = true ] && echo "${YELLOW}DRY-RUN (No changes applied)${NC}" || echo "${GREEN}LIVE EXECUTION${NC}")"
echo "=================================================="

# Check Git working tree for unstaged changes (excluding untracked build dirs)
if [ "$DRY_RUN" = false ]; then
    if ! git diff --quiet || ! git diff --cached --quiet; then
        echo -e "${YELLOW}⚠️ Working tree has uncommitted modifications. These will be included in the release commit.${NC}"
    fi
fi

# Extract Recent Changes / Changelog
PREV_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
if [ -n "$PREV_TAG" ]; then
    CHANGELOG=$(git log "${PREV_TAG}..HEAD" --oneline --no-merges 2>/dev/null || echo "")
else
    CHANGELOG=$(git log -n 10 --oneline --no-merges 2>/dev/null || echo "")
fi

echo ""
echo "📝 Changes included in this release:"
if [ -n "$CHANGELOG" ]; then
    echo "$CHANGELOG" | sed 's/^/  - /'
else
    echo "  - Initial release / maintenance updates"
fi
echo ""

if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}[DRY-RUN] Files that would be updated:${NC}"
    echo "  - VERSION (set to ${NEW_VERSION})"
    echo "  - rootfs/etc/os-release (VERSION=\"${NEW_VERSION}\", BUILD_DATE=\"${BUILD_TIMESTAMP}\")"
    echo "  - tools/ziroctl/cmd/version.go (Version = \"${NEW_VERSION}\", BuildDate = \"${BUILD_DATE}\")"
    echo "  - tools/ziropkg/cmd/root.go (Version = \"${NEW_VERSION}\")"
    echo "  - images/docker/Dockerfile (LABEL version=\"${NEW_VERSION}\")"
    echo -e "${YELLOW}[DRY-RUN] Git operations that would be executed:${NC}"
    echo "  - git commit -m \"chore(release): bump version to ${TAG}\""
    echo "  - git tag -a \"${TAG}\" -m \"Release ${TAG} (${BUILD_DATE})\""
    if [ "$PUSH_REMOTE" = true ]; then
        echo "  - git push origin ${CURRENT_BRANCH} && git push origin ${TAG}"
    fi
    echo -e "\n${GREEN}Dry run completed successfully. No files or git state modified.${NC}"
    exit 0
fi

# Update VERSION file
echo "$NEW_VERSION" > "$REPO_ROOT/VERSION"
echo "✓ Updated VERSION -> $NEW_VERSION"

# Update rootfs/etc/os-release and rootfs/etc/ziro-release
for rel in "$REPO_ROOT/rootfs/etc/os-release" "$REPO_ROOT/rootfs/etc/ziro-release"; do
    if [ -f "$rel" ]; then
        cat > "$rel" <<EOF
NAME="Ziro-OS"
VERSION="${NEW_VERSION}"
ID=ziro-os
PRETTY_NAME="Ziro-OS ${NEW_VERSION}"
HOME_URL="https://github.com/ziro-os/ziro-os"
BUILD_DATE="${BUILD_TIMESTAMP}"
ARCH="arm64"
EOF
        echo "✓ Updated $(basename "$rel")"
    fi
done

# Update tools/ziroctl/cmd/version.go
ZIROCTL_VERSION_FILE="$REPO_ROOT/tools/ziroctl/cmd/version.go"
if [ -f "$ZIROCTL_VERSION_FILE" ]; then
    # Use perl/sed for cross-platform in-place replacement
    sed -i.bak -E "s/Version   = \".*\"/Version   = \"${NEW_VERSION}\"/" "$ZIROCTL_VERSION_FILE"
    sed -i.bak -E "s/BuildDate = \".*\"/BuildDate = \"${BUILD_DATE}\"/" "$ZIROCTL_VERSION_FILE"
    rm -f "${ZIROCTL_VERSION_FILE}.bak"
    echo "✓ Updated tools/ziroctl/cmd/version.go"
fi

# Update tools/ziropkg/cmd/root.go
ZIROPKG_ROOT_FILE="$REPO_ROOT/tools/ziropkg/cmd/root.go"
if [ -f "$ZIROPKG_ROOT_FILE" ]; then
    sed -i.bak -E "s/Version = \".*\"/Version = \"${NEW_VERSION}\"/" "$ZIROPKG_ROOT_FILE"
    rm -f "${ZIROPKG_ROOT_FILE}.bak"
    echo "✓ Updated tools/ziropkg/cmd/root.go"
fi

# Update images/docker/Dockerfile
DOCKERFILE="$REPO_ROOT/images/docker/Dockerfile"
if [ -f "$DOCKERFILE" ]; then
    sed -i.bak -E "s/version=\".*\"/version=\"${NEW_VERSION}\"/" "$DOCKERFILE"
    rm -f "${DOCKERFILE}.bak"
    echo "✓ Updated images/docker/Dockerfile"
fi

# Stage files for git commit
git add \
    "$REPO_ROOT/VERSION" \
    "$REPO_ROOT/rootfs/etc/os-release" \
    "$REPO_ROOT/rootfs/etc/ziro-release" \
    "$REPO_ROOT/tools/ziroctl/cmd/version.go" \
    "$REPO_ROOT/tools/ziropkg/cmd/root.go" \
    "$REPO_ROOT/images/docker/Dockerfile"

COMMIT_MSG="chore(release): bump version to ${TAG} [skip ci]"
git commit -m "$COMMIT_MSG"
echo "✓ Created Git release commit: $COMMIT_MSG"

# Construct tag annotation message
TAG_MSG="Release ${TAG} (${BUILD_DATE})"
if [ -n "$CUSTOM_NOTES" ]; then
    TAG_MSG="${TAG_MSG}"$'\n\n'"${CUSTOM_NOTES}"
fi
if [ -n "$CHANGELOG" ]; then
    TAG_MSG="${TAG_MSG}"$'\n\n'"Changelog:"$'\n'"${CHANGELOG}"
fi

# Delete existing local tag if re-tagging
if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "⚠️ Tag $TAG already exists locally; updating..."
    git tag -d "$TAG" >/dev/null
fi

git tag -a "$TAG" -m "$TAG_MSG"
echo "✓ Created annotated Git tag: $TAG"

# Push to Remote
if [ "$PUSH_REMOTE" = true ]; then
    REMOTE_URL=$(git remote get-url origin 2>/dev/null || echo "")
    if [ -n "$REMOTE_URL" ]; then
        echo "Pushing ${CURRENT_BRANCH} and tag ${TAG} to origin..."
        git push origin "$CURRENT_BRANCH"
        git push origin "$TAG"
        echo "✅ Pushed commit and tag to remote successfully!"
    else
        echo -e "${YELLOW}⚠️ No remote 'origin' configured. Push skipped.${NC}"
        echo "You can push manually with: git push origin ${CURRENT_BRANCH} && git push origin ${TAG}"
    fi
else
    echo "Push skipped (--no-push enabled)."
    echo "To push manually, execute:"
    echo "  git push origin ${CURRENT_BRANCH} && git push origin ${TAG}"
fi

echo ""
echo "=================================================="
echo -e "🎉 Successfully prepared Ziro-OS release ${GREEN}${TAG}${NC}!"
echo "=================================================="
echo "Next Automated Steps triggered by GitHub Actions:"
echo " 1. Multi-arch rootfs & initramfs builds (x86_64, arm64)"
echo " 2. Bootable hybrid ISO generation"
echo " 3. Multi-arch Docker base image push to ghcr.io"
echo " 4. GitHub Release publication with SHA256SUMS"
echo " 5. GitHub Pages download catalog deployment"
echo "=================================================="
