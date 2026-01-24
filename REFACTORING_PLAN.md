# CKB Light Client Storage Refactoring Plan

## Current Status (Phase 1 - Completed ✅)

### What Was Done

This phase focused on reducing code duplication and adding SQLite support while laying the groundwork for a complete Service layer refactoring.

#### 1. Unified Storage Iterator Abstraction (✅ Completed)

**Files Created:**
- `light-client-lib/src/storage/db/iterator.rs` (107 lines)
  - `StorageIterator` trait with unified `collect_iterator()` method
  - `IteratorDirection` enum (Forward/Reverse)
  - `KVPair` struct for unified key-value pairs
  - Automatic conversions for RocksDB `Direction` and IndexedDB `CursorDirection`

**Benefits:**
- All three backends (RocksDB, SQLite, IndexedDB) expose the same iterator interface
- Business logic can be written once and work with any backend

#### 2. Shared Helper Functions (✅ Completed)

**Files Created:**
- `light-client-lib/src/service_helpers.rs` (123 lines)
  - `build_query_options()` - constructs query parameters from SearchKey
  - `build_filter_options()` - parses filter criteria (capacity, data length, block ranges)
  - `MAX_PREFIX_SEARCH_SIZE` constant

**Files Modified:**
- `light-client-bin/src/rpc.rs` - **Deleted 104 lines** of duplicate code
- `wasm/light-client-wasm/src/lib.rs` - **Deleted 106 lines** of duplicate code

**Benefits:**
- Eliminated ~210 lines of duplicate helper code
- Single source of truth for query building logic
- Both RPC and WASM use the same tested implementations

#### 3. SQLite Storage Backend (✅ Completed)

**Files Created:**
- `light-client-lib/src/storage/db/sqlite.rs` (948 lines)
  - Complete SQLite implementation matching RocksDB API
  - All 30+ public methods implemented
  - `StorageIterator` trait implementation
  - `Batch` struct for atomic operations
  - Full trait implementations: `CellDataProvider`, `HeaderProvider`, `CellProvider`

**Files Modified:**
- `light-client-lib/Cargo.toml` - Added `sqlite` feature flag
- `light-client-lib/src/storage/db/mod.rs` - Added conditional compilation for 3 backends

**Storage Backend Options:**
```rust
// RocksDB (default)
#[cfg(all(not(target_arch = "wasm32"), not(feature = "sqlite")))]

// SQLite (feature flag)
#[cfg(all(not(target_arch = "wasm32"), feature = "sqlite"))]

// IndexedDB (wasm)
#[cfg(target_arch = "wasm32")]
```

**Benefits:**
- Users can choose between RocksDB and SQLite via feature flag
- SQLite may be easier to debug/inspect (standard SQL tools)
- Same API, different underlying storage

#### 4. Storage Trait Definition (✅ Completed)

**Files Created:**
- `light-client-lib/src/storage/storage_trait.rs` (149 lines)
  - `LightClientStorage` trait defining the complete storage interface
  - 30+ methods covering all storage operations
  - Type aliases for complex function types (`TakeWhileFn`, `FilterMapFn`)

**Benefits:**
- Clear contract for what a storage backend must implement
- Foundation for complete Service layer refactoring
- Documentation of the storage API

### Code Quality

✅ All compilation targets pass:
- `cargo check -p ckb-light-client-lib` (RocksDB)
- `cargo check -p ckb-light-client-lib --features sqlite` (SQLite)
- `cargo check --target wasm32-unknown-unknown -p light-client-wasm` (IndexedDB)

✅ All clippy checks pass with `--deny warnings`

### Statistics

**Code Added:** 1,327 lines
- service_helpers.rs: 123 lines
- iterator.rs: 107 lines
- sqlite.rs: 948 lines
- storage_trait.rs: 149 lines

**Code Removed:** 235 lines (duplicate code)

**Net Change:** +1,092 lines (but with SQLite backend and abstractions)

**Duplicate Code Eliminated:** ~210 lines

---

## Next Phase (Phase 2 - Service Layer Refactoring)

### Problem Statement

Currently, `get_cells()`, `get_transactions()`, and `get_cells_capacity()` methods contain **~500 lines of identical business logic** duplicated between:
- `light-client-bin/src/rpc.rs` (RPC implementation)
- `wasm/light-client-wasm/src/lib.rs` (WASM implementation)

The only difference is:
- RPC directly uses RocksDB's iterator API
- WASM directly uses IndexedDB's cursor API

### Goal

Create a unified `Service` struct that contains all business logic once, using the `LightClientStorage` trait for storage operations.

### Architecture (Target State)

```
┌─────────────────────────────────────────────────────────┐
│              RPC Binary / WASM Module                   │
│  (Thin wrappers - just parameter conversion)            │
├─────────────────────────────────────────────────────────┤
│                Unified Service Struct                    │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Business Logic (written once):                   │  │
│  │  - get_cells()                                    │  │
│  │  - get_transactions()                             │  │
│  │  - get_cells_capacity()                           │  │
│  │  - get_scripts()                                  │  │
│  │  - set_scripts()                                  │  │
│  │  - ... all other methods                          │  │
│  └───────────────────────────────────────────────────┘  │
│                          ↓                               │
│              LightClientStorage Trait                    │
│                (interface abstraction)                   │
├──────────────────┬──────────────────┬──────────────────┤
│   RocksDB impl   │   SQLite impl    │  IndexedDB impl  │
│   (native)       │   (native)       │   (wasm)         │
└──────────────────┴──────────────────┴──────────────────┘
```

### Implementation Plan

#### Step 1: Implement LightClientStorage Trait for All Backends

**Tasks:**
1. Implement trait for RocksDB (`native.rs`)
   - Most methods already exist, just need `impl LightClientStorage for Storage`
   - Estimated: 50 lines

2. Implement trait for SQLite (`sqlite.rs`)
   - Most methods already exist, just need `impl LightClientStorage for Storage`
   - Estimated: 50 lines

3. Implement trait for IndexedDB (`browser.rs`)
   - Most methods already exist, just need `impl LightClientStorage for Storage`
   - May need to adjust some async methods
   - Estimated: 100 lines

**Estimated Effort:** ~200 lines of trait implementations

#### Step 2: Create Unified Service Struct

**File to Create:** `light-client-lib/src/service.rs`

**Content:**
```rust
pub struct LightClientService<S: LightClientStorage> {
    storage: Arc<S>,
    // ... other fields if needed
}

impl<S: LightClientStorage> LightClientService<S> {
    pub fn new(storage: Arc<S>) -> Self {
        Self { storage }
    }
    
    pub fn get_cells(
        &self,
        search_key: SearchKey,
        order: Order,
        limit: u32,
        after_cursor: Option<&[u8]>,
    ) -> Result<Pagination<Cell>> {
        // Move all business logic from rpc.rs here
        // Use self.storage.collect_iterator() instead of direct DB calls
    }
    
    pub fn get_transactions(/* ... */) -> Result<Pagination<Transaction>> {
        // Move all business logic from rpc.rs here
    }
    
    pub fn get_cells_capacity(/* ... */) -> Result<CellsCapacity> {
        // Move all business logic from rpc.rs here
    }
    
    // ... all other methods
}
```

**Estimated Effort:** ~800 lines (moving existing logic, not writing new code)

#### Step 3: Update RPC to Use Service

**File to Modify:** `light-client-bin/src/rpc.rs`

**Changes:**
```rust
pub struct LightClientRpcImpl {
    service: Arc<LightClientService<Storage>>,
    // ... other fields
}

impl LightClientRpc for LightClientRpcImpl {
    fn get_cells(/* ... */) -> Result<Pagination<Cell>> {
        // Thin wrapper - just convert types and call service
        self.service.get_cells(/* ... */)
            .map_err(|e| Error::internal(e))
    }
}
```

**Estimated Effort:** ~200 lines (mostly type conversions)

#### Step 4: Update WASM to Use Service

**File to Modify:** `wasm/light-client-wasm/src/lib.rs`

**Changes:**
```rust
static SERVICE: OnceCell<LightClientService<Storage>> = OnceCell::new();

#[wasm_bindgen]
pub fn get_cells(/* ... */) -> Result<JsValue, JsValue> {
    let service = SERVICE.get().ok_or("not initialized")?;
    let result = service.get_cells(/* ... */)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(serde_wasm_bindgen::to_value(&result)?)
}
```

**Estimated Effort:** ~200 lines (mostly type conversions)

### Expected Results

**Code Reduction:**
- Delete ~500 lines of duplicate business logic
- Replace with ~1,200 lines of unified Service + trait implementations
- **Net reduction in complexity** (single source of truth)

**Benefits:**
1. **Zero Duplication** - Business logic written once
2. **Easier Testing** - Test Service once, works everywhere
3. **Storage Flexibility** - Easy to add new backends (e.g., PostgreSQL)
4. **Type Safety** - Trait ensures all backends implement required methods
5. **Maintainability** - Bug fixes in one place benefit all platforms

### Timeline Estimate

- **Step 1 (Trait impls):** 2-3 hours
- **Step 2 (Service struct):** 4-6 hours
- **Step 3 (RPC refactor):** 1-2 hours
- **Step 4 (WASM refactor):** 1-2 hours
- **Testing & Debugging:** 2-3 hours

**Total:** 10-16 hours of focused work

### Testing Strategy

1. **Unit Tests:**
   - Test Service methods with mock storage
   - Verify each backend's trait implementation

2. **Integration Tests:**
   - Run existing tests with RocksDB
   - Run existing tests with SQLite feature
   - Run existing tests with WASM target

3. **Compatibility:**
   - Ensure all three backends produce identical results
   - Verify performance is acceptable

---

## Migration Guide (For When Phase 2 is Done)

### Using SQLite Instead of RocksDB

**Cargo.toml:**
```toml
[dependencies]
ckb-light-client-lib = { version = "0.5", features = ["sqlite"] }
```

**Code:**
```rust
// Same API, just enable the feature flag at compile time
let storage = Storage::new("path/to/db.sqlite")?;
// Everything else stays the same!
```

### Creating a New Storage Backend

1. Create new module in `light-client-lib/src/storage/db/`
2. Implement `LightClientStorage` trait
3. Add conditional compilation in `db/mod.rs`
4. That's it! Service layer automatically works with it.

---

## Questions for Discussion

1. **Async/Sync:** IndexedDB is inherently async. Do we need an async version of `LightClientStorage` trait, or should we handle async internally?

2. **Error Types:** Should we unify error types across all backends, or allow each backend to use its own error type?

3. **Performance:** Should we benchmark RocksDB vs SQLite to understand tradeoffs?

4. **API Stability:** Should we version the `LightClientStorage` trait since it's a public interface?

---

## References

- **Current Commit:** refactor: add unified storage abstraction and SQLite backend support
- **Related Issue:** Code duplication between RPC and WASM (94% identical code)
- **Original Problem:** ~738 lines in RPC vs ~931 lines in WASM with massive duplication
