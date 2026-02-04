//! Unified iterator types for different storage backends (RocksDB, IndexedDB, SQLite)

// On wasm32, re-export IteratorDirection and KVPair from db-common to avoid duplication
#[cfg(target_arch = "wasm32")]
pub use light_client_db_common::{IteratorDirection, KVPair};

/// Direction for iteration (forward or backward)
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IteratorDirection {
    Forward,
    Reverse,
}

/// Key-Value pair returned by the iterator
#[cfg(not(target_arch = "wasm32"))]
pub struct KVPair {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}
