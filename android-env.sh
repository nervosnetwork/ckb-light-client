#!/usr/bin/env bash
# Common environment setup for Android cross-compilation
#
# Usage: source this file from build scripts
#   source android-env.sh
#
# After sourcing, the following are configured:
#   - CC/CXX/AR/LINKER for aarch64-linux-android
#   - RocksDB cross-compilation flags
#   - BINDGEN_EXTRA_CLANG_ARGS
#   - Android stubs compiled and linked via RUSTFLAGS

set -e

# --- NDK Discovery ---

if [ -z "$ANDROID_NDK_HOME" ] || [ ! -d "$ANDROID_NDK_HOME" ]; then
    echo "ANDROID_NDK_HOME not set or invalid, searching for NDK..."
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

if [ -z "$ANDROID_NDK_HOME" ] || [ ! -d "$ANDROID_NDK_HOME" ]; then
    echo "ERROR: Android NDK not found!"
    echo ""
    echo "Please set ANDROID_NDK_HOME, e.g.:"
    echo "  export ANDROID_NDK_HOME=\$HOME/Android/Sdk/ndk/<version>"
    echo ""
    echo "Or download NDK from: https://developer.android.com/ndk/downloads"
    exit 1
fi

# --- Host Platform Detection ---

if [ -d "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64" ]; then
    NDK_HOST="linux-x86_64"
elif [ -d "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64" ]; then
    NDK_HOST="darwin-x86_64"
elif [ -d "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-arm64" ]; then
    NDK_HOST="darwin-arm64"
else
    echo "ERROR: Could not detect NDK host platform"
    exit 1
fi

export ANDROID_API_LEVEL=${ANDROID_API_LEVEL:-21}
NDK_BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin"

echo "NDK: $ANDROID_NDK_HOME"
echo "NDK Host: $NDK_HOST"
echo "API Level: $ANDROID_API_LEVEL"

if [ ! -f "$NDK_BIN/aarch64-linux-android${ANDROID_API_LEVEL}-clang" ]; then
    echo "ERROR: NDK toolchain not found at $NDK_BIN"
    exit 1
fi

# --- Rust Target ---

rustup target add aarch64-linux-android 2>/dev/null || true

# --- Cross-Compilation Environment ---

export CC_aarch64_linux_android="$NDK_BIN/aarch64-linux-android${ANDROID_API_LEVEL}-clang"
export CXX_aarch64_linux_android="$NDK_BIN/aarch64-linux-android${ANDROID_API_LEVEL}-clang++"
export AR_aarch64_linux_android="$NDK_BIN/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$NDK_BIN/aarch64-linux-android${ANDROID_API_LEVEL}-clang"

# --- RocksDB Flags ---

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

export BINDGEN_EXTRA_CLANG_ARGS="--sysroot=$SYSROOT --target=aarch64-linux-android -D__ANDROID_API__=${ANDROID_API_LEVEL}"

# --- Nix Compatibility ---

if [ -n "$NIX_LD_LIBRARY_PATH" ]; then
    export LD_LIBRARY_PATH="$NIX_LD_LIBRARY_PATH"
fi

# --- Android Stubs ---

STUBS_DIR="$(pwd)/target/android-stubs"
mkdir -p "$STUBS_DIR"

if [ -f "android-stubs.c" ]; then
    echo "Compiling Android compatibility stubs..."
    $CC_aarch64_linux_android -c android-stubs.c -o "$STUBS_DIR/android-stubs.o"
    $AR_aarch64_linux_android rcs "$STUBS_DIR/libandroid_stubs.a" "$STUBS_DIR/android-stubs.o"
    export RUSTFLAGS="-L $STUBS_DIR -l static=android_stubs"
else
    echo "Note: android-stubs.c not found, skipping stubs"
    export RUSTFLAGS=""
fi

echo ""
