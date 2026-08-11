#!/usr/bin/env bash
# Build CKB Light Client JNI shared library for Android
#
# Output: target/aarch64-linux-android/release/libckb_light_client_lib.so

set -e

echo "======================================"
echo "CKB Light Client - Android JNI Build"
echo "======================================"
echo ""

# Setup cross-compilation environment
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/android-env.sh"

echo "Building JNI library for aarch64-linux-android..."
echo ""

cargo build --release \
    --target aarch64-linux-android \
    --package ckb-light-client-lib \
    --features jni-bridge,portable

echo ""
echo "======================================"
echo "Build completed successfully!"
echo "======================================"
echo ""

SO_FILE="target/aarch64-linux-android/release/libckb_light_client_lib.so"
if [ -f "$SO_FILE" ]; then
    SIZE=$(ls -lh "$SO_FILE" | awk '{print $5}')
    echo "Output: $SO_FILE ($SIZE)"
fi

# Copy libc++_shared.so from NDK to jniLibs
JNILIBS_DIR="android-app/app/src/main/jniLibs/arm64-v8a"
mkdir -p "$JNILIBS_DIR"

NDK_HOST_DIR="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST"
CPP_SHARED="$NDK_HOST_DIR/sysroot/usr/lib/aarch64-linux-android/libc++_shared.so"
if [ -f "$CPP_SHARED" ]; then
    cp "$CPP_SHARED" "$JNILIBS_DIR/"
    echo "Copied libc++_shared.so to $JNILIBS_DIR/"
else
    echo "Warning: libc++_shared.so not found at $CPP_SHARED"
fi
echo ""
