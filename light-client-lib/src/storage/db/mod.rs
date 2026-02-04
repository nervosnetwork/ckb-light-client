mod iterator;
pub use iterator::{IteratorDirection, IteratorStart, KVPair};

// Native platforms: Use RocksDB by default, SQLite when feature is enabled
#[cfg(all(not(target_arch = "wasm32"), not(feature = "sqlite")))]
mod native;
#[cfg(all(not(target_arch = "wasm32"), not(feature = "sqlite")))]
pub use native::{Batch, Storage};

#[cfg(all(not(target_arch = "wasm32"), feature = "sqlite"))]
mod sqlite;
#[cfg(all(not(target_arch = "wasm32"), feature = "sqlite"))]
pub use sqlite::{Batch, Storage};

// WASM platform: Use IndexedDB
#[cfg(target_arch = "wasm32")]
mod browser;
#[cfg(target_arch = "wasm32")]
pub use browser::{Batch, Storage};
