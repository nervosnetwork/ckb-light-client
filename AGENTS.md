# AGENTS.md - CKB Light Client Development Guide

This guide provides essential information for AI coding agents working in the ckb-light-client repository.

## Project Overview

CKB light client reference implementation based on RFC 44 and RFC 45. This is a Rust workspace project with both native (Rust) and WebAssembly (Wasm) targets.

**Workspace Structure:**
- `light-client-lib/` - Core library (native + wasm, `ckb-light-client-lib`)
- `light-client-bin/` - CLI binary (native only, `ckb-light-client`)
- `wasm/light-client-wasm/` - Wasm bindings
- `wasm/light-client-db-worker/` - Database worker for browsers
- `wasm/light-client-db-common/` - Common database code
- `wasm/light-client-js/` - JavaScript/TypeScript wrapper

**Rust Toolchain:** 1.92.0 (specified in `rust-toolchain`)

## Build Commands

### Native Rust
```bash
# Build all native targets
make build
cargo build

# Build release
cargo build --release

# Build specific package
cargo build -p ckb-light-client
cargo build -p ckb-light-client-lib
```

### WebAssembly
```bash
# Install dependencies and build all wasm packages
make build-wasm

# Equivalent to:
npm install
npm run build -ws
```

## Testing

### Run All Tests
```bash
# Run native tests using cargo-nextest (required)
make test

# Runs:
cargo nextest run --hide-progress-bar --success-output immediate \
  --failure-output immediate -p ckb-light-client-lib -p ckb-light-client
```

### Run Tests on macOS
```bash
# Use portable feature on macOS
make test-portable

# Runs with feature flag:
cargo nextest run --features portable ...
```

### Run Single Test
```bash
# Run a specific test by name
cargo nextest run -p <package-name> <test-name>

# Examples:
cargo nextest run -p ckb-light-client-lib test_verify_blocks_proof
cargo nextest run -p ckb-light-client synchronizer::tests
```

### Run Wasm Tests
```bash
# Run wasm-pack tests for browser environment
make test-wasm

# Runs:
wasm-pack test --node ./wasm/light-client-db-common/
```

### JavaScript/TypeScript Tests
```bash
# Run tests in wasm workspace packages
npm test -ws

# Or for specific package:
cd wasm/light-client-js && npm test
```

## Linting & Formatting

### Format Check
```bash
# Check formatting (CI mode)
make fmt

# Runs:
cargo fmt --all --check

# Auto-fix formatting
cargo fmt --all
```

### Clippy Linting
```bash
# Run clippy with warnings as errors
make clippy

# This runs two separate checks:
# 1. Wasm targets
cargo clippy --target wasm32-unknown-unknown \
  -p light-client-wasm -p ckb-light-client-lib \
  -p light-client-db-common -p light-client-db-worker \
  --locked -- --deny warnings

# 2. Native targets
cargo clippy -p ckb-light-client --locked -- --deny warnings
```

## Code Style Guidelines

### Imports
- Group imports by: std library, external crates, internal crates
- Use explicit imports rather than glob imports
- Example from codebase:
  ```rust
  use std::{fmt, result};
  
  use thiserror::Error;
  
  use crate::storage;
  ```

### Error Handling
- Use `thiserror` for error types
- Define custom error enums with `#[derive(Error, Debug)]`
- Use descriptive error messages with `#[error("...")]`
- Create custom `Result<T>` type aliases:
  ```rust
  pub type Result<T> = result::Result<T, Error>;
  ```
- Provide helper methods for error construction:
  ```rust
  impl Error {
      pub fn config<T: fmt::Display>(inner: T) -> Self {
          Self::Config(inner.to_string())
      }
  }
  ```

### Types and Conversions
- Implement `From` trait for type conversions between internal and external types
- Use `#[serde(rename_all = "snake_case")]` for JSON serialization
- Use `#[cfg(target_arch = "wasm32")]` for platform-specific code
- Example:
  ```rust
  impl From<ScriptType> for storage::ScriptType {
      fn from(st: ScriptType) -> Self {
          match st {
              ScriptType::Lock => Self::Lock,
              ScriptType::Type => Self::Type,
          }
      }
  }
  ```

### Naming Conventions
- Use `snake_case` for functions, variables, and modules
- Use `PascalCase` for types, structs, enums, and traits
- Use `SCREAMING_SNAKE_CASE` for constants
- Prefer descriptive names over abbreviations

### Modules and Organization
- Keep module declarations in `lib.rs` or `main.rs`
- Use `mod.rs` files for module organization
- Separate concerns: protocols, storage, utils, service, error

### Testing
- Place unit tests in the same file or dedicated `tests` submodule
- Use `#[cfg(test)]` attribute for test-only code
- Use `#[macro_use]` for test macros when needed
- Integration tests go in workspace package's `tests/` directory

### Documentation
- Add doc comments for public APIs
- Use `///` for documentation comments
- Include examples in doc comments when helpful

### Conditional Compilation
- Use `#[cfg(not(target_arch = "wasm32"))]` for native-only code (e.g., RocksDB)
- Use `#[cfg(target_arch = "wasm32")]` for wasm-only code (e.g., IndexedDB)
- Keep platform-specific code isolated in separate modules when possible

### Warnings
- CI enforces `-D warnings` (all warnings treated as errors)
- Use `#![allow(clippy::mutable_key_type)]` sparingly and only when justified
- Address clippy warnings rather than silencing them

## Development Workflow

1. Make code changes
2. Run `cargo fmt --all` to format code
3. Run `make clippy` to check for lints
4. Run `make test` (or `make test-portable` on macOS) for native tests
5. Run `make test-wasm` if touching wasm code
6. For wasm changes, run `npm test -ws` for JS/TS tests

## CI Configuration

The project uses GitHub Actions (`.github/workflows/ci.yaml`):
- Runs on: Ubuntu, macOS, Windows
- Steps: Format check, Clippy, Native tests, Wasm tests, Code coverage
- All warnings treated as errors with `RUSTFLAGS: -D warnings`
