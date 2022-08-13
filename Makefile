CARGO_TARGET_DIR ?= target
COVERAGE_RUST_TOOLCHAIN ?= nightly-2022-07-30
GRCOV_OUTPUT ?= coverage-report.info
GRCOV_EXCL_START = ^\s*((log::)?(trace|debug|info|warn|error)|(debug_)?assert(_eq|_ne|_error_eq))!\($$
GRCOV_EXCL_STOP  = ^\s*\)(;)?$$
GRCOV_EXCL_LINE = \s*((log::)?(trace|debug|info|warn|error)|(debug_)?assert(_eq|_ne|_error_eq))!\(.*\)(;)?$$

coverage-clean:
	rm -rf "${CARGO_TARGET_DIR}/debug/deps" "${GRCOV_OUTPUT}" "${GRCOV_OUTPUT:.info=}"

coverage-install-tools:
	rustup --toolchain "${COVERAGE_RUST_TOOLCHAIN}" component add llvm-tools-preview
	grcov --version || cargo +"${COVERAGE_TOOLCHAIN}" install grcov

coverage-run-unittests:
	RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort" \
		RUSTDOCFLAGS="-Cpanic=abort" \
		CARGO_INCREMENTAL=0 \
			cargo +"${COVERAGE_RUST_TOOLCHAIN}" test --all

coverage-collect-data:
	RUSTUP_TOOLCHAIN="${COVERAGE_RUST_TOOLCHAIN}" \
	grcov "${CARGO_TARGET_DIR}/debug/deps" --binary-path "${CARGO_TARGET_DIR}/debug/" \
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
