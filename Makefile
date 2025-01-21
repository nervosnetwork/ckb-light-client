CARGO_TARGET_DIR ?= target
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
build:
	cargo build

build-wasm:
	npm install
	npm run build -ws

test:
	cargo nextest run --hide-progress-bar --success-output immediate --failure-output immediate -p ckb-light-client-lib -p ckb-light-client

test-portable:
	cargo nextest run --features portable --hide-progress-bar --success-output immediate --failure-output immediate -p ckb-light-client-lib -p ckb-light-client

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
