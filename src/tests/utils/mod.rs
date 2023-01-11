use env_logger::{Builder, Target};
use log::LevelFilter;

mod chain;
mod network_context;

pub(crate) use chain::MockChain;
pub(crate) use network_context::MockNetworkContext;

use crate::storage::Storage;

pub(crate) fn setup() {
    let _ = Builder::new()
        .filter_module("ckb_stop_handler", LevelFilter::Off)
        .filter_module("ckb_light_client", LevelFilter::Trace)
        .target(Target::Stdout)
        .is_test(true)
        .try_init();
    println!();
}

pub(crate) fn new_storage(prefix: &str) -> Storage {
    let tmp_dir = tempfile::Builder::new().prefix(prefix).tempdir().unwrap();
    Storage::new(tmp_dir.path().to_str().unwrap())
}
