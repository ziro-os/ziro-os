#!/bin/bash
# Package build script for Ziro-OS

set -e

PACKAGE_NAME="$1"
TARGET_ARCH="${TARGET_ARCH:-x86_64}"

if [ -z "$PACKAGE_NAME" ]; then
    echo "Usage: $0 <package-name>"
    echo "Environment: TARGET_ARCH=${TARGET_ARCH}"
    exit 1
fi

PACKAGE_DIR="base"
MANIFEST_FILE="$PACKAGE_DIR/$PACKAGE_NAME.yaml"
ROOTFS_DIR="../rootfs"

echo "Building package: $PACKAGE_NAME for architecture: $TARGET_ARCH"

if [ ! -f "$MANIFEST_FILE" ]; then
    echo "Package manifest not found: $MANIFEST_FILE"
    exit 1
fi

echo "Building package: $PACKAGE_NAME"

# Parse YAML manifest (simplified)
NAME=$(grep "^name:" "$MANIFEST_FILE" | cut -d' ' -f2)
VERSION=$(grep "^version:" "$MANIFEST_FILE" | cut -d' ' -f2 | tr -d '"')
BUILD_TYPE=$(grep "^build_type:" "$MANIFEST_FILE" | cut -d' ' -f2 | tr -d '"')

# Get architecture-specific URL
if [ "$TARGET_ARCH" = "arm64" ] || [ "$TARGET_ARCH" = "aarch64" ]; then
    URL=$(grep "^url_arm64:" "$MANIFEST_FILE" | cut -d' ' -f2- | tr -d '"')
    if [ -z "$URL" ]; then
        URL=$(grep "^url:" "$MANIFEST_FILE" | cut -d' ' -f2- | tr -d '"')
        # Replace architecture placeholders
        URL=$(echo "$URL" | sed 's/{ARCH}/arm64/g' | sed 's/{GOARCH}/arm64/g')
    fi
else
    URL=$(grep "^url_x86_64:" "$MANIFEST_FILE" | cut -d' ' -f2- | tr -d '"')
    if [ -z "$URL" ]; then
        URL=$(grep "^url:" "$MANIFEST_FILE" | cut -d' ' -f2- | tr -d '"')
        # Replace architecture placeholders
        URL=$(echo "$URL" | sed 's/{ARCH}/amd64/g' | sed 's/{GOARCH}/amd64/g')
    fi
fi

echo "Package: $NAME v$VERSION"
echo "Source: $URL"
echo "Build type: $BUILD_TYPE"

# Create build directory
BUILD_DIR="build/$NAME-$VERSION"
mkdir -p "$BUILD_DIR"

# Download source if not cached
SOURCE_FILE="$BUILD_DIR/$(basename "$URL")"
if [ ! -f "$SOURCE_FILE" ]; then
    echo "Downloading source..."
    curl -L "$URL" -o "$SOURCE_FILE"
fi

case "$BUILD_TYPE" in
    "binary")
        echo "Installing pre-built binary..."
        if [[ "$SOURCE_FILE" == *.tar.* ]]; then
            tar -xf "$SOURCE_FILE" -C "$BUILD_DIR" --strip-components=0
            
            # Handle CNI plugins specially
            if [[ "$NAME" == cni-* ]]; then
                echo "Installing CNI plugins..."
                mkdir -p "$ROOTFS_DIR/opt/cni/bin"
                # CNI plugins are in the root of the tar file
                find "$BUILD_DIR" -maxdepth 1 -name "bridge" -o -name "loopback" -o -name "host-local" -o -name "portmap" -o -name "firewall" | while read -r plugin; do
                    if [ -f "$plugin" ]; then
                        echo "Installing CNI plugin: $(basename "$plugin")"
                        cp "$plugin" "$ROOTFS_DIR/opt/cni/bin/"
                        chmod +x "$ROOTFS_DIR/opt/cni/bin/$(basename "$plugin")"
                    fi
                done
            else
                # Copy all binaries from bin/ directory if it exists
                if [ -d "$BUILD_DIR/bin" ]; then
                    cp "$BUILD_DIR/bin"/* "$ROOTFS_DIR/usr/bin/" 2>/dev/null || true
                fi
                # Also look for the specific binary name
                find "$BUILD_DIR" -name "$NAME" -type f | head -1 | xargs -I {} cp {} "$ROOTFS_DIR/usr/bin/" 2>/dev/null || true
            fi
        else
            cp "$SOURCE_FILE" "$ROOTFS_DIR/usr/bin/$NAME"
            chmod +x "$ROOTFS_DIR/usr/bin/$NAME"
        fi
        ;;
    "autotools")
        echo "Building with autotools for $TARGET_ARCH..."
        # Extract source to a subdirectory
        EXTRACT_DIR="$BUILD_DIR/src"
        mkdir -p "$EXTRACT_DIR"
        tar -xf "$SOURCE_FILE" -C "$EXTRACT_DIR" --strip-components=1
        cd "$EXTRACT_DIR"
        
        # Set cross-compilation variables
        if [ "$TARGET_ARCH" = "arm64" ] || [ "$TARGET_ARCH" = "aarch64" ]; then
            export CC="aarch64-linux-gnu-gcc"
            export CXX="aarch64-linux-gnu-g++"
            export AR="aarch64-linux-gnu-ar"
            export STRIP="aarch64-linux-gnu-strip"
            CONFIGURE_HOST="--host=aarch64-linux-gnu"
        else
            CONFIGURE_HOST=""
        fi
        
        ./configure --prefix=/usr --enable-static --disable-shared $CONFIGURE_HOST
        make -j$(nproc)
        make DESTDIR="$BUILD_DIR/install" install
        cp -r "$BUILD_DIR/install"/* "$ROOTFS_DIR/"
        ;;
    "make")
        echo "Building with make for $TARGET_ARCH..."
        # Extract source to a subdirectory
        EXTRACT_DIR="$BUILD_DIR/src"
        mkdir -p "$EXTRACT_DIR"
        tar -xf "$SOURCE_FILE" -C "$EXTRACT_DIR" --strip-components=1
        cd "$EXTRACT_DIR"
        
        # Set cross-compilation variables for busybox
        if [ "$TARGET_ARCH" = "arm64" ] || [ "$TARGET_ARCH" = "aarch64" ]; then
            export CROSS_COMPILE="aarch64-linux-gnu-"
            export ARCH="arm64"
        else
            export CROSS_COMPILE=""
            export ARCH="x86_64"
        fi
        
        make defconfig
        make -j$(nproc) LDFLAGS=--static
        make CONFIG_PREFIX="$ROOTFS_DIR" install
        ;;
    *)
        echo "Unknown build type: $BUILD_TYPE"
        exit 1
        ;;
esac

echo "Package $NAME built and installed successfully"