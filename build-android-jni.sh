#!/usr/bin/env bash
# Build script for CKB Light Client JNI (Android)
#
# Builds for multiple Android architectures: arm64-v8a, armeabi-v7a, x86_64

set -e

echo "======================================"
echo "CKB Light Client - Android JNI Build"
echo "======================================"
echo ""

# Try to find Android NDK if not already set
if [ -z "$ANDROID_NDK_HOME" ] || [ ! -d "$ANDROID_NDK_HOME" ]; then
    echo "ANDROID_NDK_HOME not set or invalid, searching for NDK..."
    # Try common locations
    for ndk_path in \
        "$ANDROID_HOME/ndk/"* \
        "$HOME/Android/Sdk/ndk/"* \
        "/usr/local/android-ndk"* \
        "$HOME/soft/ndk/"* \
        "$HOME/android-ndk"*; do
        if [ -d "$ndk_path/toolchains/llvm/prebuilt" ]; then
            export ANDROID_NDK_HOME="$ndk_path"
            echo "Found NDK at: $ANDROID_NDK_HOME"
            break
        fi
    done
fi

# Check if NDK is available
if [ -z "$ANDROID_NDK_HOME" ] || [ ! -d "$ANDROID_NDK_HOME" ]; then
    echo "ERROR: Android NDK not found!"
    echo ""
    echo "Please install Android NDK and set ANDROID_NDK_HOME environment variable."
    echo ""
    echo "To install NDK:"
    echo "  1. Install Android Studio from https://developer.android.com/studio"
    echo "  2. Open SDK Manager: Tools > SDK Manager"
    echo "  3. Go to SDK Tools tab"
    echo "  4. Check 'NDK (Side by side)' and click Apply"
    echo ""
    echo "Then set ANDROID_NDK_HOME:"
    echo "  export ANDROID_NDK_HOME=\$HOME/Android/Sdk/ndk/<version>"
    echo ""
    echo "Or download standalone NDK from:"
    echo "  https://developer.android.com/ndk/downloads"
    echo ""
    exit 1
fi

# Detect host platform
if [ -d "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64" ]; then
    NDK_HOST="linux-x86_64"
elif [ -d "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64" ]; then
    NDK_HOST="darwin-x86_64"
else
    echo "ERROR: Could not detect NDK host platform"
    exit 1
fi

export ANDROID_API_LEVEL=21
NDK_BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin"

echo "Using NDK: $ANDROID_NDK_HOME"
echo "NDK Host: $NDK_HOST"
echo "API Level: $ANDROID_API_LEVEL"
echo ""

# Check if the required tools are available
if [ ! -f "$NDK_BIN/aarch64-linux-android${ANDROID_API_LEVEL}-clang" ]; then
    echo "ERROR: NDK toolchain not found!"
    echo "Expected: $NDK_BIN/aarch64-linux-android${ANDROID_API_LEVEL}-clang"
    exit 1
fi

# Add Rust Android targets
echo "Adding Rust Android targets..."
rustup target add aarch64-linux-android

# Configure environment for Android cross-compilation
export CC_aarch64_linux_android="$NDK_BIN/aarch64-linux-android${ANDROID_API_LEVEL}-clang"
export CXX_aarch64_linux_android="$NDK_BIN/aarch64-linux-android${ANDROID_API_LEVEL}-clang++"
export AR_aarch64_linux_android="$NDK_BIN/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$NDK_BIN/aarch64-linux-android${ANDROID_API_LEVEL}-clang"

# RocksDB and build configuration
SYSROOT="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/sysroot"
ROCKSDB_DISABLE_FLAGS="-DROCKSDB_NO_DYNAMIC_EXTENSION"
ROCKSDB_DISABLE_FLAGS="$ROCKSDB_DISABLE_FLAGS -DROCKSDB_LITE"
ROCKSDB_DISABLE_FLAGS="$ROCKSDB_DISABLE_FLAGS -Dposix_madvise=madvise"
ROCKSDB_DISABLE_FLAGS="$ROCKSDB_DISABLE_FLAGS -Dfread_unlocked=fread"
ROCKSDB_DISABLE_FLAGS="$ROCKSDB_DISABLE_FLAGS -DPOSIX_MADV_NORMAL=MADV_NORMAL"
ROCKSDB_DISABLE_FLAGS="$ROCKSDB_DISABLE_FLAGS -DPOSIX_MADV_RANDOM=MADV_RANDOM"
ROCKSDB_DISABLE_FLAGS="$ROCKSDB_DISABLE_FLAGS -DPOSIX_MADV_SEQUENTIAL=MADV_SEQUENTIAL"
ROCKSDB_DISABLE_FLAGS="$ROCKSDB_DISABLE_FLAGS -DPOSIX_MADV_WILLNEED=MADV_WILLNEED"
ROCKSDB_DISABLE_FLAGS="$ROCKSDB_DISABLE_FLAGS -DPOSIX_MADV_DONTNEED=MADV_DONTNEED"

export CXXFLAGS="-fPIC -D__ANDROID_API__=${ANDROID_API_LEVEL} $ROCKSDB_DISABLE_FLAGS"
export CFLAGS="-fPIC -D__ANDROID_API__=${ANDROID_API_LEVEL}"

export ROCKSDB_DISABLE_FALLOCATE=1
export ROCKSDB_DISABLE_SYNC_FILE_RANGE=1
export ROCKSDB_DISABLE_PTHREAD_MUTEX_ADAPTIVE_NP=1
export ROCKSDB_DISABLE_SCHED_GETCPU=1
export ROCKSDB_DISABLE_AUXV=1

# BINDGEN_EXTRA_CLANG_ARGS is set per-target in the build loop

# Set LD_LIBRARY_PATH for Nix environment
if [ -n "$NIX_LD_LIBRARY_PATH" ]; then
    export LD_LIBRARY_PATH="$NIX_LD_LIBRARY_PATH"
fi

# Compile Android stubs for missing libc functions
echo "Compiling Android compatibility stubs..."
STUBS_DIR="$(pwd)/target/android-stubs"
mkdir -p "$STUBS_DIR"

# Check if stubs file exists
if [ -f "android-stubs.c" ]; then
    $CC_aarch64_linux_android -c android-stubs.c -o "$STUBS_DIR/android-stubs.o"
    $AR_aarch64_linux_android rcs "$STUBS_DIR/libandroid_stubs.a" "$STUBS_DIR/android-stubs.o"
    export RUSTFLAGS="-L $STUBS_DIR -l static=android_stubs"
else
    echo "Note: android-stubs.c not found, skipping stubs compilation"
    export RUSTFLAGS=""
fi

echo ""
echo "Building for Android arm64-v8a..."
echo ""

TARGET=aarch64-linux-android
echo "======================================"
echo "Building for $TARGET"
echo "======================================"

# Set target-specific bindgen args
export BINDGEN_EXTRA_CLANG_ARGS="--sysroot=$SYSROOT --target=$TARGET -D__ANDROID_API__=${ANDROID_API_LEVEL}"

cargo build --release \
    --target $TARGET \
    --package ckb-light-client-lib \
    --features jni-bridge,portable

echo ""

echo ""
echo "======================================"
echo "Build completed successfully!"
echo "======================================"
echo ""
echo "Output file:"
echo "  arm64-v8a: target/aarch64-linux-android/release/libckb_light_client_lib.so"
echo ""

# Show file size
SO_FILE="target/aarch64-linux-android/release/libckb_light_client_lib.so"
if [ -f "$SO_FILE" ]; then
    SIZE=$(ls -lh "$SO_FILE" | awk '{print $5}')
    echo "File size: $SIZE"
fi
echo ""
