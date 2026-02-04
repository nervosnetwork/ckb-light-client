# CKB Light Client Storage Layer Refactoring

This document describes the storage layer refactoring that introduces unified abstractions across RocksDB (native), SQLite, and IndexedDB (browser) backends.

## Overview

The refactoring addresses code duplication across storage backends and between RPC/WASM entry points. It introduces:

1. **`StorageBackend` trait** - Low-level KV operations that each backend must implement
2. **`LightClientStorage` trait** - High-level business logic with default implementations
3. **Unified service layer** - Eliminates duplication between RPC and WASM entry points

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Entry Points                                │
│  ┌──────────────┐                    ┌──────────────────────┐   │
│  │  RPC Server  │                    │    WASM Bindings     │   │
│  │  (rpc.rs)    │                    │ (light-client-wasm)  │   │
│  └──────┬───────┘                    └──────────┬───────────┘   │
│         │                                       │               │
│         └───────────────┬───────────────────────┘               │
│                         ▼                                       │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                   Service Layer                          │   │
│  │  ┌─────────────────┐ ┌─────────────────┐ ┌────────────┐ │   │
│  │  │LightClientService│LightClientChain- │ │LightClient-│ │   │
│  │  │(cells, txs)     │ │Service          │ │NetworkSvc  │ │   │
│  │  └─────────────────┘ └─────────────────┘ └────────────┘ │   │
│  └─────────────────────────┬───────────────────────────────┘   │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              LightClientStorage Trait                    │   │
│  │  (Business logic with default implementations)           │   │
│  │  - filter_block(), rollback_to_block()                  │   │
│  │  - get/update filter scripts, matched blocks            │   │
│  │  - check points, genesis block management               │   │
│  └─────────────────────────┬───────────────────────────────┘   │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              StorageBackend Trait                        │   │
│  │  (Low-level KV operations)                               │   │
│  │  - get(), put(), delete(), batch()                      │   │
│  │  - collect_iterator()                                    │   │
│  └─────────────────────────┬───────────────────────────────┘   │
│                            ▼                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐     │
│  │   RocksDB   │  │   SQLite    │  │     IndexedDB       │     │
│  │  (native)   │  │  (native)   │  │     (browser)       │     │
│  └─────────────┘  └─────────────┘  └─────────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
```

## Key Components

### StorageBackend Trait (`storage/backend.rs`)

Defines the minimal operations each storage backend must implement:

```rust
pub trait StorageBackend: Send + Sync {
    fn get(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>>;
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()>;
    fn delete(&self, key: &[u8]) -> Result<()>;
    fn batch(&self) -> Box<dyn BatchWriter>;
    fn collect_iterator(
        &self,
        from_key: Vec<u8>,
        direction: IteratorDirection,
        take_while_fn: TakeWhileFn,
        filter_map_fn: FilterMapFn,
        skip: usize,
        limit: usize,
    ) -> Vec<KVPair>;
}
```

### BatchWriter Trait (`storage/backend.rs`)

Provides atomic batch operations:

```rust
pub trait BatchWriter {
    fn put(&mut self, key: &[u8], value: &[u8]);
    fn delete(&mut self, key: &[u8]);
    fn commit(self: Box<Self>) -> Result<()>;
}
```

### LightClientStorage Trait (`storage/storage_trait.rs`)

High-level trait with business logic. Methods with default implementations reduce duplication:

- `filter_block()` - Scans blocks and stores matching cells/transactions
- Filter scripts management (`get_filter_scripts`, `update_filter_scripts`, etc.)
- Matched blocks management
- Check points management
- Block and transaction management

### Service Layer (`service/`)

Unified service implementations shared by RPC and WASM:

- `LightClientService` - Cell and transaction queries (`get_cells`, `get_transactions`, `get_cells_capacity`)
- `LightClientChainService` - Chain state and block operations
- `LightClientNetworkService` - Network and peer management

## File Structure

```
light-client-lib/src/
├── service/
│   ├── mod.rs           # Module exports
│   ├── types.rs         # Shared types (SearchKey, Cell, Tx, etc.)
│   ├── helpers.rs       # Query building utilities
│   └── impls.rs         # Service implementations
└── storage/
    ├── mod.rs           # Module exports and shared types
    ├── backend.rs       # StorageBackend and BatchWriter traits
    ├── storage_trait.rs # LightClientStorage trait with defaults
    └── db/
        ├── mod.rs       # Database module exports
        ├── iterator.rs  # Iterator types and direction
        ├── native.rs    # RocksDB implementation
        ├── sqlite.rs    # SQLite implementation
        └── browser.rs   # IndexedDB implementation
```

## Benefits

### Code Reduction

| Area | Before | After | Reduction |
|------|--------|-------|-----------|
| `filter_block` | ~370 lines (3 copies) | ~180 lines (1 copy) | ~50% |
| RPC entry points | ~1000 lines | ~200 lines | ~80% |
| WASM entry points | ~1100 lines | ~200 lines | ~80% |

### Maintainability

- **Single source of truth** - Business logic is defined once in traits
- **Consistent behavior** - All backends behave identically
- **Easier testing** - Test trait implementations, not duplicated code
- **Type safety** - Rust's trait system ensures correct implementations

### Extensibility

Adding a new storage backend requires only implementing:
1. `StorageBackend` trait (5 methods)
2. `BatchWriter` trait (3 methods)

All business logic (50+ methods) comes for free via default implementations.

## Migration Notes

### For RPC

The RPC structs now hold service instances:

```rust
// Before
pub struct BlockFilterRpcImpl {
    swc: StorageWithChainData,
}

// After  
pub struct BlockFilterRpcImpl {
    service: LightClientService<Storage>,
    chain_service: LightClientChainService<Storage>,
}
```

### For WASM

WASM bindings now use the same service layer:

```rust
// Uses same LightClientService as RPC
let result = get_cell_service()
    .get_cells(search_key, order, limit.into(), after_cursor_json)?;
```

## Testing

All existing tests pass without modification. The refactoring is behavior-preserving.

```bash
# Run all tests
cargo nextest run --features portable -p ckb-light-client-lib -p ckb-light-client

# Run clippy
cargo clippy -p ckb-light-client-lib -p ckb-light-client --locked -- --deny warnings
```
