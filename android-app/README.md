# CKB Light Client - Android App

Minimal Android wrapper app that runs ckb-light-client binary on Android devices and displays logs in real-time.

## Features

- Runs ckb-light-client natively on Android (arm64-v8a)
- Real-time log viewing with scrollable TextView
- Start/Stop controls
- Automatic binary extraction and config setup
- Uses app private storage for data
- RPC on localhost only (127.0.0.1:9000)

## Prerequisites

### For Building the Rust Binary

1. **Android NDK r26+**
   - Install via Android Studio: Tools > SDK Manager > SDK Tools > NDK (Side by side)
   - Or download from: https://developer.android.com/ndk/downloads
   - Set environment: `export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/<version>`

2. **Rust Android Target**
   - Already installed: `aarch64-linux-android`

### For Building the Android App

1. **Android Studio** (recommended) or **Command-line tools**
   - Android SDK with API level 34
   - Gradle 8.5+ (will be downloaded automatically by Gradle wrapper)
   - JDK 8 or higher

## Build Instructions

### Step 1: Build Rust Binary for Android

```bash
cd /home/exec/Projects/github.com/nervosnetwork/ckb-light-client

# Run the build script (it will check for NDK and guide you)
./build-android.sh
```

The script will:
- Check for Android NDK installation
- Set up cross-compilation environment
- Build the binary for arm64-v8a
- Output: `target/aarch64-linux-android/release/ckb-light-client` (~15-25 MB)

### Step 2: Build Android APK

#### Option A: Using Android Studio (Recommended)

1. Open Android Studio
2. Select "Open an existing project"
3. Navigate to `/home/exec/Projects/github.com/nervosnetwork/ckb-light-client/android-app`
4. Wait for Gradle sync to complete
5. Build > Build Bundle(s) / APK(s) > Build APK(s)
6. APK will be at: `app/build/outputs/apk/release/app-release.apk`

#### Option B: Using Command Line

```bash
cd /home/exec/Projects/github.com/nervosnetwork/ckb-light-client/android-app

# Build release APK
./gradlew assembleRelease

# Or build debug APK
./gradlew assembleDebug
```

**Note:** The Gradle build will automatically copy the Rust binary from `target/aarch64-linux-android/release/ckb-light-client` to `app/src/main/jniLibs/arm64-v8a/libckb_light_client.so`.

### Step 3: Install on Device

```bash
# Install via adb
adb install app/build/outputs/apk/release/app-release.apk

# Or install debug version
adb install app/build/outputs/apk/debug/app-debug.apk
```

## Usage

1. **Launch the app** on your Android device
2. The app will automatically:
   - Extract the ckb-light-client binary to app storage
   - Create a modified mainnet.toml config with Android paths
   - Display "Ready to start" when setup is complete
3. **Press "Start"** to launch ckb-light-client
4. **View logs** in real-time in the scrollable log view showing:
   - Version and build information
   - Network connection status
   - Block synchronization progress
   - RPC server startup
5. **Press "Stop"** to terminate the process

## Log Viewing

The app displays all stdout/stderr output from the ckb-light-client binary in a scrollable TextView with:
- Monospace font for easy reading
- Auto-scroll to show latest logs
- Real-time streaming as logs are generated

You can scroll through the logs at any time. The app captures:
- Startup messages (version, git hash, build time)
- Network events (peer connections, bootnodes)
- Sync progress (header downloads, verification)
- RPC server status
- Any errors or warnings

## Storage

The app uses private storage for all data:

```
/data/data/com.nervosnetwork.ckblightclient/files/
├── ckb-light-client          # Executable binary
├── mainnet.toml              # Config with Android paths
└── data/
    ├── store/                # RocksDB database (grows to 500MB-2GB)
    └── network/              # Peer information
```

All data is automatically deleted when the app is uninstalled.

## Network & RPC

- **P2P Network:** Connects to CKB mainnet bootnodes (configured in mainnet.toml)
- **RPC Server:** Runs on `127.0.0.1:9000` (localhost only, not accessible from outside the app)
- **Permissions:** Requires `INTERNET` and `ACCESS_NETWORK_STATE`

## Troubleshooting

### Binary won't build

```bash
# Check NDK installation
ls $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android21-clang

# Check Rust target
rustup target list --installed | grep aarch64-linux-android
```

### Gradle build fails - binary not found

```bash
# Make sure you built the Rust binary first
ls -lh target/aarch64-linux-android/release/ckb-light-client

# If missing, run:
./build-android.sh
```

### App crashes on startup

```bash
# Check logs
adb logcat | grep -E "(CKBLightClient|AndroidRuntime)"

# Check binary permissions
adb shell ls -l /data/data/com.nervosnetwork.ckblightclient/files/ckb-light-client
# Should show: -rwx------
```

### No logs appear in the app

- The binary may not have started - check `adb logcat` for errors
- Ensure the binary has execute permissions
- Check that the config file was created correctly

### Network connection fails

- Ensure device has WiFi or mobile data connection
- Check INTERNET permission in AndroidManifest.xml
- Verify bootnodes are reachable

## Development

### Project Structure

```
android-app/
├── app/
│   ├── build.gradle.kts              # App module build config
│   └── src/main/
│       ├── AndroidManifest.xml       # App permissions and components
│       ├── java/com/nervosnetwork/ckblightclient/
│       │   └── MainActivity.kt       # Main app logic
│       ├── res/layout/
│       │   └── activity_main.xml     # UI layout
│       ├── assets/
│       │   └── mainnet.toml          # Config template
│       └── jniLibs/arm64-v8a/
│           └── libckb_light_client.so  # Rust binary (copied at build time)
├── build.gradle.kts                  # Root build config
├── settings.gradle.kts               # Project settings
└── gradle/wrapper/
    └── gradle-wrapper.properties     # Gradle version
```

### Modifying the App

- **Change config:** Edit `app/src/main/assets/mainnet.toml` or modify the path replacement logic in `MainActivity.kt`
- **Adjust UI:** Edit `app/src/main/res/layout/activity_main.xml`
- **Change package name:** Update `namespace` in `app/build.gradle.kts` and rename package directory
- **Add features:** Extend `MainActivity.kt` (e.g., add RPC client, display sync status, etc.)

## Version

- CKB Light Client: 0.5.3
- Min SDK: 21 (Android 5.0)
- Target SDK: 34 (Android 14)
- ABI: arm64-v8a only

## License

Same as ckb-light-client: MIT
