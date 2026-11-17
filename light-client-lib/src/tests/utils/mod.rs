use env_logger::{Builder, Target};
use log::LevelFilter;
use tempfile::TempDir;

mod chain;
mod network_context;

pub(crate) use chain::MockChain;
pub(crate) use network_context::MockNetworkContext;

use crate::storage::Storage;

static CLOCK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// ckb-systemtime's fake clock and enable flag are process-global. Keep every
/// test that changes them exclusive, including under cargo test's parallel runner.
pub(crate) struct TestClock {
    // Drop the fake clock before releasing the lock to the next test.
    clock: ckb_systemtime::FaketimeGuard,
    _lock: std::sync::MutexGuard<'static, ()>,
}

pub(crate) fn faketime() -> TestClock {
    let lock = CLOCK_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    TestClock {
        clock: ckb_systemtime::faketime(),
        _lock: lock,
    }
}

impl TestClock {
    pub(crate) fn set_faketime(&self, time: u64) {
        self.clock.set_faketime(time);
    }
}

pub(crate) fn setup() {
    let _ = Builder::new()
        .filter_module("ckb_stop_handler", LevelFilter::Off)
        .filter_module("ckb_light_client", LevelFilter::Trace)
        .target(Target::Stdout)
        .is_test(true)
        .try_init();
    println!();
}

/// Create a new storage for testing.
/// Returns both the Storage and the TempDir to ensure the temp directory
/// lives as long as the storage is being used.
pub(crate) fn new_storage(prefix: &str) -> (Storage, TempDir) {
    let tmp_dir = tempfile::Builder::new().prefix(prefix).tempdir().unwrap();
    let storage = Storage::new(tmp_dir.path().to_str().unwrap());
    (storage, tmp_dir)
}
