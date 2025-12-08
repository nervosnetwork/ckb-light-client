//! Cross-platform database error.

#[cfg(not(target_arch = "wasm32"))]
pub use rocksdb::Error as DatabaseError;

#[cfg(target_arch = "wasm32")]
#[derive(Debug)]
pub struct DatabaseError(String);

#[cfg(target_arch = "wasm32")]
impl std::fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(target_arch = "wasm32")]
impl From<idb::Error> for DatabaseError {
    fn from(value: idb::Error) -> Self {
        DatabaseError(value.to_string())
    }
}
