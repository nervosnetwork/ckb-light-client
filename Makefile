CARGO_TARGET_DIR ?= $(shell pwd)/target
COVERAGE_PROFRAW_DIR ?= ${CARGO_TARGET_DIR}/coverage
GRCOV_OUTPUT ?= coverage-report.info
GRCOV_EXCL_START = ^\s*((log::)?(trace|debug|info|warn|error)|(debug_)?assert(_eq|_ne|_error_eq))!\($$
GRCOV_EXCL_STOP  = ^\s*\)(;)?$$
GRCOV_EXCL_LINE = \s*((log::)?(trace|debug|info|warn|error)|(debug_)?assert(_eq|_ne|_error_eq))!\(.*\)(;)?$$

fmt:
	cargo fmt --all --check

clippy:
	# cargo clippy --workspace --locked -- --deny warnings
	# Run clippy for wasm targets
	cargo clippy --target wasm32-unknown-unknown -p light-client-wasm -p ckb-light-client-lib -p light-client-db-common -p light-client-db-worker --locked -- --deny warnings
	# Run clippy for native targets
	cargo clippy -p ckb-light-client --locked -- --deny warnings

clippy-sqlite:
	# Run clippy for native targets with sqlite feature
	cargo clippy --features sqlite -p ckb-light-client-lib -p ckb-light-client --locked -- --deny warnings

build:
	cargo build

build-wasm:
	npm install
	npm run build -ws

test:
	cargo nextest run --hide-progress-bar --success-output immediate --failure-output immediate -p ckb-light-client-lib -p ckb-light-client

test-portable:
	cargo nextest run --features portable --hide-progress-bar --success-output immediate --failure-output immediate -p ckb-light-client-lib -p ckb-light-client

test-sqlite:
	cargo nextest run --features sqlite --hide-progress-bar --success-output immediate --failure-output immediate -p ckb-light-client-lib -p ckb-light-client

test-wasm:
	wasm-pack test --node ./wasm/light-client-db-common/

coverage-clean:
	rm -rf "${CARGO_TARGET_DIR}/*.profraw" "${GRCOV_OUTPUT}" "${GRCOV_OUTPUT:.info=}"

coverage-install-tools:
	rustup component add llvm-tools-preview
	grcov --version || cargo install --locked grcov

coverage-run-unittests:
	mkdir -p "${COVERAGE_PROFRAW_DIR}"
	rm -f "${COVERAGE_PROFRAW_DIR}/*.profraw"
	RUSTFLAGS="${RUSTFLAGS} -Cinstrument-coverage" \
		LLVM_PROFILE_FILE="${COVERAGE_PROFRAW_DIR}/unittests-%p-%m.profraw" \
			cargo test --workspace --exclude light-client-db-common --exclude light-client-db-worker --exclude light-client-wasm

coverage-collect-data:
	grcov "${COVERAGE_PROFRAW_DIR}" --binary-path "${CARGO_TARGET_DIR}/debug/" \
		-s . -t lcov --branch --ignore-not-existing \
		--ignore "/*" \
		--ignore "*/tests/*" \
		--ignore "*/tests.rs" \
		--excl-br-start "${GRCOV_EXCL_START}" --excl-br-stop "${GRCOV_EXCL_STOP}" \
		--excl-start    "${GRCOV_EXCL_START}" --excl-stop    "${GRCOV_EXCL_STOP}" \
		--excl-br-line  "${GRCOV_EXCL_LINE}" \
		--excl-line     "${GRCOV_EXCL_LINE}" \
		-o "${GRCOV_OUTPUT}"

coverage-generate-report:
	genhtml -o "${GRCOV_OUTPUT:.info=}" "${GRCOV_OUTPUT}"


android-package:
	@echo "======================================"
	@echo "Building Android APK"
	@echo "======================================"
	@echo ""
	@echo "📦 Step 1: Building native JNI libraries..."
	./build-android-jni.sh
	@echo ""
	@echo "📦 Step 2: Copying JNI libraries to Android project..."
	mkdir -p android-app/app/src/main/jniLibs/arm64-v8a
	cp target/aarch64-linux-android/release/libckb_light_client_lib.so android-app/app/src/main/jniLibs/arm64-v8a/
	@if [ -f android-app/app/src/main/jniLibs/arm64-v8a/libc++_shared.so ]; then \
		echo "  ✓ libc++_shared.so already present"; \
	else \
		echo "  ⚠ libc++_shared.so not found (build-android-jni.sh should have copied it)"; \
	fi
	@echo ""
	@echo "📱 Step 3: Building Android APK with Gradle..."
	cd android-app && chmod +x gradlew && ANDROID_HOME=$${ANDROID_HOME:-$$HOME/Android/Sdk} ./gradlew assembleDebug
	@echo ""
	@echo "======================================"
	@echo "✅ Build completed successfully!"
	@echo "======================================"
	@echo ""
	@echo "📦 APK location:"
	@ls -lh android-app/app/build/outputs/apk/debug/app-debug.apk 2>/dev/null || echo "  APK not found"
	@echo ""
	@echo "To install on device: make android-install"
	@echo ""

android-install:
	@echo "📲 Installing APK to connected device..."
	@if [ ! -f android-app/app/build/outputs/apk/debug/app-debug.apk ]; then \
		echo "❌ APK not found. Run 'make android-package' first."; \
		exit 1; \
	fi
	adb install -r android-app/app/build/outputs/apk/debug/app-debug.apk
	@echo "✅ APK installed successfully!"
	@echo "🚀 Launching app..."
	adb shell monkey -p com.nervosnetwork.ckblightclient -c android.intent.category.LAUNCHER 1
	@echo ""
	@echo "📱 Monitor logs with: adb logcat | grep -i 'ckb\|LightClient'"
	@echo ""

android-clean:
	@echo "🧹 Cleaning Android build artifacts..."
	rm -rf android-app/app/build
	rm -rf android-app/app/src/main/jniLibs
	rm -rf android-app/.gradle
	rm -rf target/aarch64-linux-android
	rm -rf target/android-stubs
	@echo "✅ Android build artifacts cleaned!"
	@echo ""

.PHONY: fmt clippy build build-wasm test test-portable test-wasm coverage-clean coverage-install-tools coverage-run-unittests coverage-collect-data coverage-generate-report android-package android-install android-clean
