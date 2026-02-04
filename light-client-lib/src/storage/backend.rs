// StorageBackend trait - low-level KV operations that each backend must implement
//
// This trait abstracts the basic storage operations, allowing business logic to be
// shared across RocksDB, SQLite, and IndexedDB backends.

use crate::error::Result;

use super::{IteratorDirection, IteratorStart, KVPair};

/// Type alias for the take_while function used in iterator operations
pub type TakeWhileFn = Box<dyn Fn(&[u8]) -> bool + Send + 'static>;

/// Type alias for the filter_map function used in iterator operations
/// Unified to (key, value) signature for consistency across all backends
pub type FilterMapFn = Box<dyn Fn(&[u8], &[u8]) -> Option<Vec<u8>> + Send + 'static>;

/// Trait for batch write operations
///
/// Each storage backend provides its own implementation of this trait.
/// The batch allows multiple put/delete operations to be committed atomically.
pub trait BatchWriter {
    /// Add a key-value pair to the batch
    fn put(&mut self, key: &[u8], value: &[u8]);

    /// Add a delete operation to the batch
    fn delete(&mut self, key: &[u8]);

    /// Commit all operations in the batch atomically
    fn commit(self) -> Result<()>;
}

/// Low-level storage backend trait
///
/// This trait defines the minimal set of operations that each storage backend
/// (RocksDB, SQLite, IndexedDB) must implement. Business logic is implemented
/// as default methods in `LightClientStorage` which builds on top of this trait.
pub trait StorageBackend: Send + Sync {
    /// The batch type for this storage backend
    type Batch: BatchWriter;

    // ========== Basic KV operations ==========

    /// Get value by key
    fn get(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>>;

    /// Put key-value pair
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()>;

    /// Delete key
    fn delete(&self, key: &[u8]) -> Result<()>;

    // ========== Batch operations ==========

    /// Create a new batch for atomic writes
    fn batch(&self) -> Self::Batch;

    // ========== Iterator operations ==========

    /// Collect items using iterator with custom filter and map functions
    ///
    /// This is the core method for implementing get_cells, get_transactions, etc.
    /// All backends must implement this with consistent behavior.
    ///
    /// # Arguments
    ///
    /// * `start` - Starting position for iteration (From for inclusive, After for exclusive)
    /// * `direction` - Direction of iteration (Forward or Reverse)
    /// * `take_while_fn` - Function to determine when to stop iteration (e.g., prefix matching)
    /// * `filter_map_fn` - Function to filter and optionally transform (key, value) pairs
    /// * `limit` - Maximum number of items to return
    ///
    /// # Returns
    ///
    /// A vector of key-value pairs that match the criteria
    fn collect_iterator(
        &self,
        start: IteratorStart,
        direction: IteratorDirection,
        take_while_fn: TakeWhileFn,
        filter_map_fn: FilterMapFn,
        limit: usize,
    ) -> Vec<KVPair>;
}
