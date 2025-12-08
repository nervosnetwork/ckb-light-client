//! Cross-platform time primitives.

#[cfg(target_arch = "wasm32")]
pub use web_time::{Duration, Instant};

#[cfg(not(target_arch = "wasm32"))]
pub use std::time::{Duration, Instant};
