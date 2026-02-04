//! Unified iterator types for different storage backends (RocksDB, IndexedDB, SQLite)

// On wasm32, re-export types from db-common to avoid duplication
#[cfg(target_arch = "wasm32")]
pub use light_client_db_common::{IteratorDirection, IteratorStart, KVPair};

/// Direction for iteration (forward or backward)
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IteratorDirection {
    Forward,
    Reverse,
}

/// Starting position for iteration
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IteratorStart {
    /// Start from the specified key (inclusive)
    From(Vec<u8>),
    /// Start after the specified key (exclusive, used for cursor-based pagination)
    After(Vec<u8>),
}

#[cfg(not(target_arch = "wasm32"))]
impl IteratorStart {
    /// Get the key to start from
    pub fn key(&self) -> &[u8] {
        match self {
            IteratorStart::From(key) | IteratorStart::After(key) => key,
        }
    }

    /// Whether to skip the first matching key
    pub fn should_skip_first(&self) -> bool {
        matches!(self, IteratorStart::After(_))
    }
}

/// Key-Value pair returned by the iterator
#[cfg(not(target_arch = "wasm32"))]
pub struct KVPair {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}
