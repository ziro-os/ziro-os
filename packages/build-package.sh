#!/bin/bash
# Package build script for Ziro-OS

set -e

PACKAGE_NAME="$1"
if [ -z "$PACKAGE_NAME" ]; then
    echo "Usage: $0 <package-name>"
    exit 1
fi

PACKAGE_DIR="base"
MANIFEST_FILE="$PACKAGE_DIR/$PACKAGE_NAME.yaml"

if [ ! -f "$MANIFEST_FILE" ]; then
    echo "Package manifest not found: $MANIFEST_FILE"
    exit 1
fi

echo "Building package: $PACKAGE_NAME"

# Parse YAML manifest (simplified - would use proper YAML parser)
NAME=$(grep "^name:" "$MANIFEST_FILE" | cut -d' ' -f2)
VERSION=$(grep "^version:" "$MANIFEST_FILE" | cut -d' ' -f2 | tr -d '"')
URL=$(grep "^url:" "$MANIFEST_FILE" | cut -d' ' -f2 | tr -d '"')

echo "Package: $NAME v$VERSION"
echo "Source: $URL"

# Create build directory
BUILD_DIR="build/$NAME-$VERSION"
mkdir -p "$BUILD_DIR"

# Download source (placeholder)
echo "Downloading source..."
# wget "$URL" -O "$BUILD_DIR/source.tar.gz"
# tar -xzf "$BUILD_DIR/source.tar.gz" -C "$BUILD_DIR" --strip-components=1

echo "Package build placeholder for $NAME"
echo "Would compile and install to rootfs"