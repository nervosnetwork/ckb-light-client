//! Unified iterator types for different storage backends (RocksDB, IndexedDB, SQLite)

#[cfg(not(target_arch = "wasm32"))]
use rocksdb::Direction;

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

#[cfg(not(target_arch = "wasm32"))]
impl From<IteratorDirection> for Direction {
    fn from(dir: IteratorDirection) -> Self {
        match dir {
            IteratorDirection::Forward => Direction::Forward,
            IteratorDirection::Reverse => Direction::Reverse,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<Direction> for IteratorDirection {
    fn from(dir: Direction) -> Self {
        match dir {
            Direction::Forward => IteratorDirection::Forward,
            Direction::Reverse => IteratorDirection::Reverse,
        }
    }
}

/// Key-Value pair returned by the iterator
#[cfg(not(target_arch = "wasm32"))]
pub struct KVPair {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[cfg(not(target_arch = "wasm32"))]
impl From<(Vec<u8>, Vec<u8>)> for KVPair {
    fn from((key, value): (Vec<u8>, Vec<u8>)) -> Self {
        KVPair { key, value }
    }
}
