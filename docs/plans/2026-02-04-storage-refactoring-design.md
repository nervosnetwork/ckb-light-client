# Storage Layer Refactoring Design

**Date**: 2026-02-04  
**Status**: Draft  
**Goal**: Reduce code duplication across storage backends and unify interfaces

## Background

The current codebase has three storage backends:
- `native.rs` (RocksDB) - ~1200 lines
- `sqlite.rs` (SQLite) - ~1100 lines  
- `browser.rs` (IndexedDB) - ~1600 lines

Each backend duplicates significant business logic that should be shared:
- `filter_block` (~150 lines each)
- `rollback_to_block` (~80 lines each)
- `update_filter_scripts` (~60 lines each)
- `init_genesis_block` (~50 lines each)

Additionally, the SQLite implementation is incomplete (missing input consumption tracking).

## Design

### Trait Layering

Split `LightClientStorage` into two tiers:

```
┌─────────────────────────────────────┐
│     LightClientStorage (high-level) │  ← Business logic with default implementations
│  filter_block, rollback_to_block,   │
│  update_filter_scripts, etc.        │
├─────────────────────────────────────┤
│     StorageBackend (low-level)      │  ← Each backend must implement
│  get, put, delete, batch,           │
│  collect_iterator                   │
└─────────────────────────────────────┘
```

### StorageBackend Trait

```rust
pub trait StorageBackend: Send + Sync {
    // Basic KV operations
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;
    fn put(&self, key: &[u8], value: &[u8]) -> Result<()>;
    fn delete(&self, key: &[u8]) -> Result<()>;
    
    // Batch operations
    fn batch(&self) -> Box<dyn BatchWriter>;
    
    // Iterator (unified signature)
    fn collect_iterator<F, M>(
        &self,
        from_key: &[u8],
        direction: IteratorDirection,
        take_while: F,
        filter_map: M,
        skip: usize,
        limit: usize,
    ) -> Vec<KVPair>
    where
        F: Fn(&[u8]) -> bool,
        M: Fn(&[u8], &[u8]) -> Option<Vec<u8>>;
}

pub trait BatchWriter {
    fn put(&mut self, key: &[u8], value: &[u8]);
    fn delete(&mut self, key: &[u8]);
    fn commit(self: Box<Self>) -> Result<()>;
}
```

### LightClientStorage with Default Implementations

```rust
pub trait LightClientStorage: StorageBackend {
    fn filter_block(&self, block: Block) {
        // Shared business logic (~150 lines)
        // Uses self.get(), self.batch() etc.
    }
    
    fn rollback_to_block(&self, to_number: BlockNumber) {
        // Shared logic (~80 lines)
    }
    
    fn update_filter_scripts(&self, scripts: Vec<ScriptStatus>, command: SetScriptsCommand) {
        // Shared logic (~60 lines)
    }
    
    // ... other methods with default implementations
}

// Blanket implementation
impl<T: StorageBackend> LightClientStorage for T {}
```

### Iterator Interface Unification

Current inconsistency:
| Backend | filter_map signature |
|---------|---------------------|
| native.rs | `Fn(&[u8]) -> Option<Vec<u8>>` (key only) |
| sqlite.rs | `Fn(&[u8], &[u8]) -> Option<Vec<u8>>` (key + value) |
| browser.rs | `FilterMapType` enum wrapping both |

**Unified to (key, value) two-parameter signature** because:
1. More flexible - can access value for filtering
2. Backward compatible - ignore value when only key is needed
3. Eliminates `FilterMapType` enum in browser.rs

### Type Unification

Remove duplicate type definitions:

| service layer | storage layer | Action |
|--------------|---------------|--------|
| `service::types::ScriptStatus` | `storage::ScriptStatus` | Delete service version, re-export |
| `service::types::ScriptType` | `storage::ScriptType` | Delete service version, re-export |
| `service::types::SetScriptsCommand` | `storage::SetScriptsCommand` | Delete service version, re-export |

```rust
// service/types.rs - change to re-export
pub use crate::storage::{ScriptStatus, ScriptType, SetScriptsCommand};
```

## File Structure After Refactoring

```
light-client-lib/src/storage/
├── mod.rs                    # re-exports, Key/Value enums
├── types.rs                  # ScriptStatus, ScriptType, SetScriptsCommand (canonical)
├── backend.rs                # StorageBackend trait + BatchWriter trait
├── storage.rs                # LightClientStorage trait + default implementations
├── iterator.rs               # IteratorDirection, KVPair (keep as-is)
└── db/
    ├── mod.rs                # Conditional compilation
    ├── native.rs             # RocksDB: only implement StorageBackend (~300 lines)
    ├── sqlite.rs             # SQLite: only implement StorageBackend (~300 lines)
    └── browser.rs            # IndexedDB: only implement StorageBackend (~400 lines)
```

### Estimated Code Reduction

| File | Before | After | Reduction |
|------|--------|-------|-----------|
| native.rs | ~1200 lines | ~300 lines | -900 lines |
| sqlite.rs | ~1100 lines | ~300 lines | -800 lines |
| browser.rs | ~1600 lines | ~400 lines | -1200 lines |
| storage.rs (new) | - | ~400 lines | +400 lines |
| **Total** | ~3900 lines | ~1400 lines | **-2500 lines** |

## Migration Strategy

### Phase 1: Infrastructure (Low Risk)
1. Create `StorageBackend` trait and `BatchWriter` trait
2. Unify iterator signatures
3. Unify types (delete duplicates in service::types)

### Phase 2: Extract Shared Logic (Medium Risk)
1. Move business logic from `native.rs` to `LightClientStorage` default implementations
2. Modify `native.rs` to only implement `StorageBackend`
3. Verify all native tests pass

### Phase 3: Apply to Other Backends (Medium Risk)
1. Modify `sqlite.rs` to use shared implementation
2. Modify `browser.rs` to use shared implementation  
3. Run all tests (native + wasm)

### Testing Strategy

Each phase requires:
- `make test` (native tests)
- `make test-wasm` (wasm tests)
- `make clippy` (lint checks)

### Estimated Timeline

| Phase | Duration | Main Work |
|-------|----------|-----------|
| Phase 1 | 1 day | Trait definitions, type unification |
| Phase 2 | 2 days | Extract logic, modify native.rs |
| Phase 3 | 2 days | Modify sqlite.rs, browser.rs |

## Risks and Mitigations

### 1. Browser Backend Async Differences
- IndexedDB uses SharedArrayBuffer + Worker communication
- `batch.commit()` may need special handling
- **Mitigation**: BatchWriter trait's `commit` returns `Result<()>`, error handling by each backend

### 2. Platform-specific RwLock
Current code has `#[cfg(target_arch = "wasm32")]` conditionals for RwLock access.
- **Decision**: Not in storage layer scope, handle separately

### 3. Performance Impact
- Default implementations may introduce minor indirect call overhead
- **Assessment**: Business logic overhead >> indirect call overhead, negligible impact

## Out of Scope (YAGNI)

The following are **not** in scope for this refactoring:
- RPC layer refactoring (already thin wrappers)
- WASM bindings refactoring (already reuse Service layer)
- New storage backends (e.g., Memory backend)
- Performance optimizations (e.g., async batch support)

## Notes

### SQLite Completeness
The current SQLite `filter_block` implementation is incomplete - it doesn't handle input consumption (UTXO deletion) or transaction history recording. This will be fixed as part of the refactoring by adopting the shared implementation.
