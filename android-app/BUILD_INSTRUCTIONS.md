# Building the CKB Light Client Android APK

The Rust binary has been successfully built for Android! Now you need to build the Android APK.

## Prerequisites

You need the Android SDK with build tools to compile the APK. Here are your options:

### Option 1: Using Android Studio (Recommended - Easiest)

1. **Install Android Studio** from https://developer.android.com/studio

2. **Open the project:**
   - Launch Android Studio
   - Select "Open an existing project"
   - Navigate to: `/home/exec/Projects/github.com/nervosnetwork/ckb-light-client/android-app`

3. **Let Android Studio sync:**
   - It will automatically download required SDK components
   - Wait for Gradle sync to complete

4. **Build the APK:**
   - Menu: Build → Build Bundle(s) / APK(s) → Build APK(s)
   - Or click the "Build" button in the toolbar

5. **Find your APK:**
   - Location: `app/build/outputs/apk/debug/app-debug.apk` (debug build)
   - Location: `app/build/outputs/apk/release/app-release.apk` (release build)

### Option 2: Command Line (Requires Android SDK)

If you prefer command-line building, you need to install the Android SDK first:

#### Step 1: Install Android Command Line Tools

```bash
# Download Android command line tools
cd ~
mkdir -p Android/Sdk/cmdline-tools
cd Android/Sdk/cmdline-tools

# Download latest command line tools from:
# https://developer.android.com/studio#command-line-tools-only
# For Linux:
wget https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip
unzip commandlinetools-linux-9477386_latest.zip
mv cmdline-tools latest
```

#### Step 2: Install Required SDK Components

```bash
export ANDROID_HOME=$HOME/Android/Sdk
export PATH=$ANDROID_HOME/cmdline-tools/latest/bin:$PATH

# Accept licenses
yes | sdkmanager --licenses

# Install required components
sdkmanager "platform-tools" "platforms;android-34" "build-tools;34.0.0"
```

#### Step 3: Build with Gradle

```bash
cd /home/exec/Projects/github.com/nervosnetwork/ckb-light-client/android-app

# Build debug APK
./gradlew assembleDebug

# Or build release APK (unsigned)
./gradlew assembleRelease
```

### Option 3: Use a Build Server / CI

If you have access to a CI system with Android build capabilities (GitHub Actions, GitLab CI, etc.), you can build there.

## After Building

### Install the APK on your device:

```bash
# Make sure your Android device is connected and USB debugging is enabled
adb devices

# Install the APK
adb install app/build/outputs/apk/debug/app-debug.apk
# or
adb install app/build/outputs/apk/release/app-release.apk
```

### Run and monitor:

```bash
# View logs from the terminal
adb logcat | grep CKBLightClient

# Or just open the app on your device and press "Start"
```

## What's Already Done

✅ Rust binary compiled for Android (arm64-v8a)
✅ Android app code complete with real-time log viewing
✅ Build configuration ready (Gradle files)
✅ Config file bundled in assets

**You just need to build the APK using one of the methods above!**

## Quick Test (Without Building APK)

If you want to test the binary directly on an Android device without building the full APK:

```bash
# Push the binary to your device
adb push target/aarch64-linux-android/release/ckb-light-client /data/local/tmp/

# Push the config
adb push config/mainnet.toml /data/local/tmp/

# Make it executable
adb shell chmod +x /data/local/tmp/ckb-light-client

# Run it (in adb shell)
adb shell
cd /data/local/tmp
./ckb-light-client run --config-file mainnet.toml
```

This will run the light client directly in adb shell, though you won't get the nice Android UI with log viewing.

## Troubleshooting

**"SDK location not found"**
- Set ANDROID_HOME: `export ANDROID_HOME=$HOME/Android/Sdk`

**"Gradle sync failed"**
- Make sure you have Java JDK installed: `java -version`
- Gradle requires JDK 17 or newer

**"Build tools not found"**
- Install via SDK Manager in Android Studio
- Or via command line: `sdkmanager "build-tools;34.0.0"`

## Need Help?

The Android app is fully implemented and ready to build. The only requirement is the Android SDK with build tools, which is most easily obtained through Android Studio.
