mod chain;
mod network_context;

pub(crate) use chain::MockChain;
pub(crate) use network_context::MockNetworkContext;

use crate::storage::Storage;

pub(crate) fn new_storage(prefix: &str) -> Storage {
    let tmp_dir = tempfile::Builder::new().prefix(prefix).tempdir().unwrap();
    Storage::new(tmp_dir.path().to_str().unwrap())
}
