//! Unified iterator abstraction for different storage backends (RocksDB, IndexedDB, SQLite)
//! This trait provides a common interface for iterating over key-value pairs with filtering.

#[cfg(not(target_arch = "wasm32"))]
use rocksdb::Direction;

/// Direction for iteration (forward or backward)
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
#[allow(dead_code)]
pub struct KVPair {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

impl From<(Vec<u8>, Vec<u8>)> for KVPair {
    fn from((key, value): (Vec<u8>, Vec<u8>)) -> Self {
        KVPair { key, value }
    }
}

/// Unified storage iterator trait
///
/// This trait provides a common interface for collecting key-value pairs from storage
/// with support for prefix matching, filtering, pagination, and bi-directional iteration.
#[allow(dead_code)]
pub trait StorageIterator {
    /// Collect key-value pairs from storage with filtering and pagination
    ///
    /// # Arguments
    ///
    /// * `from_key` - Starting key for iteration
    /// * `direction` - Direction of iteration (Forward or Reverse)
    /// * `take_while_fn` - Function to determine when to stop iteration (e.g., prefix matching)
    /// * `filter_map_fn` - Function to filter and optionally transform keys during iteration
    /// * `limit` - Maximum number of items to return
    /// * `skip` - Number of items to skip from the start
    ///
    /// # Returns
    ///
    /// A vector of key-value pairs that match the criteria
    #[allow(clippy::type_complexity)]
    fn collect_iterator(
        &self,
        from_key: Vec<u8>,
        direction: IteratorDirection,
        take_while_fn: Box<dyn Fn(&[u8]) -> bool + Send + 'static>,
        filter_map_fn: Box<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static>,
        limit: usize,
        skip: usize,
    ) -> Vec<KVPair>;
}
