#!/usr/bin/env bash
# Build script for CKB Light Client on Android (aarch64-linux-android)

set -e

echo "======================================"
echo "CKB Light Client - Android Build"
echo "======================================"
echo ""

# Set default NDK path if not already set
if [ -z "$ANDROID_NDK_HOME" ]; then
    export ANDROID_NDK_HOME=/home/exec/soft/ndk/android-ndk-r27d
    echo "Using default NDK path: $ANDROID_NDK_HOME"
fi

# Try to find Android NDK
if [ -z "$ANDROID_NDK_HOME" ] || [ ! -d "$ANDROID_NDK_HOME" ]; then
    # Try common locations
    for ndk_path in \
        "$HOME/Android/Sdk/ndk/"* \
        "$ANDROID_HOME/ndk/"* \
        "/usr/local/android-ndk" \
        "$HOME/android-ndk"*; do
        if [ -d "$ndk_path/toolchains/llvm/prebuilt" ]; then
            ANDROID_NDK_HOME="$ndk_path"
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

# Set up environment for cross-compilation
# Use full paths to avoid affecting host build scripts
export CC_aarch64_linux_android="$NDK_BIN/aarch64-linux-android${ANDROID_API_LEVEL}-clang"
export CXX_aarch64_linux_android="$NDK_BIN/aarch64-linux-android${ANDROID_API_LEVEL}-clang++"
export AR_aarch64_linux_android="$NDK_BIN/llvm-ar"
export AS_aarch64_linux_android="$NDK_BIN/aarch64-linux-android${ANDROID_API_LEVEL}-clang"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$NDK_BIN/aarch64-linux-android${ANDROID_API_LEVEL}-clang"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_AR="$NDK_BIN/llvm-ar"

# Force static linking and vendored dependencies
export OPENSSL_STATIC=1
export OPENSSL_INCLUDE_DIR=""
export OPENSSL_LIB_DIR=""

# OpenSSL specific configuration for Android
export OPENSSL_TARGET="android-arm64"
export OPENSSL_COMPILER="$NDK_BIN/aarch64-linux-android${ANDROID_API_LEVEL}-clang"

# RocksDB and bindgen configuration for Android
SYSROOT="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/sysroot"

# Disable Linux-specific features that don't exist on Android
# These defines tell RocksDB to not use Android-incompatible functions
ROCKSDB_DISABLE_FLAGS="-DROCKSDB_NO_DYNAMIC_EXTENSION"
ROCKSDB_DISABLE_FLAGS="$ROCKSDB_DISABLE_FLAGS -DROCKSDB_LITE"  # Use lite version for mobile

# Stub out missing POSIX functions for Android
# Android's Bionic libc doesn't have these, so we define them as no-ops
ROCKSDB_DISABLE_FLAGS="$ROCKSDB_DISABLE_FLAGS -Dposix_madvise=madvise"
ROCKSDB_DISABLE_FLAGS="$ROCKSDB_DISABLE_FLAGS -Dfread_unlocked=fread"
ROCKSDB_DISABLE_FLAGS="$ROCKSDB_DISABLE_FLAGS -DPOSIX_MADV_NORMAL=MADV_NORMAL"
ROCKSDB_DISABLE_FLAGS="$ROCKSDB_DISABLE_FLAGS -DPOSIX_MADV_RANDOM=MADV_RANDOM"
ROCKSDB_DISABLE_FLAGS="$ROCKSDB_DISABLE_FLAGS -DPOSIX_MADV_SEQUENTIAL=MADV_SEQUENTIAL"
ROCKSDB_DISABLE_FLAGS="$ROCKSDB_DISABLE_FLAGS -DPOSIX_MADV_WILLNEED=MADV_WILLNEED"
ROCKSDB_DISABLE_FLAGS="$ROCKSDB_DISABLE_FLAGS -DPOSIX_MADV_DONTNEED=MADV_DONTNEED"

export CXXFLAGS="-fPIC -D__ANDROID_API__=${ANDROID_API_LEVEL} $ROCKSDB_DISABLE_FLAGS"
export CFLAGS="-fPIC -D__ANDROID_API__=${ANDROID_API_LEVEL}"

# Tell RocksDB build script that Android doesn't have these POSIX features
export ROCKSDB_DISABLE_FALLOCATE=1
export ROCKSDB_DISABLE_SYNC_FILE_RANGE=1
export ROCKSDB_DISABLE_PTHREAD_MUTEX_ADAPTIVE_NP=1
export ROCKSDB_DISABLE_SCHED_GETCPU=1
export ROCKSDB_DISABLE_AUXV=1

# Configure bindgen to use Android headers (use system libclang)
export CLANG_PATH="$NDK_BIN/aarch64-linux-android${ANDROID_API_LEVEL}-clang"
export BINDGEN_EXTRA_CLANG_ARGS="--sysroot=$SYSROOT --target=aarch64-linux-android -D__ANDROID_API__=${ANDROID_API_LEVEL}"

# Set LD_LIBRARY_PATH for Nix environment
if [ -n "$NIX_LD_LIBRARY_PATH" ]; then
    export LD_LIBRARY_PATH="$NIX_LD_LIBRARY_PATH"
fi

echo "Environment configured for Android cross-compilation"
echo ""
echo "Building for target: aarch64-linux-android"
echo "This may take several minutes on first build..."
echo ""

# Compile Android stubs for missing libc functions
echo "Compiling Android compatibility stubs..."
STUBS_DIR="$(pwd)/target/android-stubs"
mkdir -p "$STUBS_DIR"
$CC_aarch64_linux_android -c android-stubs.c -o "$STUBS_DIR/android-stubs.o"
$AR_aarch64_linux_android rcs "$STUBS_DIR/libandroid_stubs.a" "$STUBS_DIR/android-stubs.o"

# Set up linker flags to use our stubs
export RUSTFLAGS="-L $STUBS_DIR -l static=android_stubs"

# Build with portable feature to disable CPU-specific optimizations for ARM64
cargo build --release --target aarch64-linux-android --features portable

echo ""
echo "======================================"
echo "Build completed successfully!"
echo "======================================"
echo ""
echo "Binary location:"
echo "  target/aarch64-linux-android/release/ckb-light-client"
echo ""
echo "Binary size:"
ls -lh target/aarch64-linux-android/release/ckb-light-client | awk '{print "  " $5}'
echo ""
echo "Verify binary:"
echo "  file target/aarch64-linux-android/release/ckb-light-client"
echo ""
