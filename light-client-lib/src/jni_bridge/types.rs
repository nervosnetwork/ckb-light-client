//! Global state management for JNI bridge
//!
//! Uses OnceLock for thread-safe singleton pattern, similar to WASM implementation.

use crate::protocols::Peers;
use crate::storage::StorageWithChainData;
use ckb_chain_spec::consensus::Consensus;
use ckb_network::NetworkController;
use jni::objects::GlobalRef;
use jni::JavaVM;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};
use tokio::runtime::Runtime;

/// State machine values
/// - 0 (INIT): Initialized but not started
/// - 1 (RUNNING): Running
/// - 2 (STOPPED): Stopped
pub static STATE: AtomicU8 = AtomicU8::new(0);

pub const STATE_INIT: u8 = 0;
pub const STATE_RUNNING: u8 = 1;
pub const STATE_STOPPED: u8 = 2;

/// Global storage with chain data
pub static STORAGE_WITH_DATA: OnceLock<StorageWithChainData> = OnceLock::new();

/// Global network controller
pub static NET_CONTROL: OnceLock<NetworkController> = OnceLock::new();

/// Global consensus
pub static CONSENSUS: OnceLock<Arc<Consensus>> = OnceLock::new();

/// Global peers manager
pub static PEERS: OnceLock<Arc<Peers>> = OnceLock::new();

/// Global tokio runtime
pub static RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Global JavaVM for callbacks
pub static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();

/// Global status callback
pub static STATUS_CALLBACK: OnceLock<GlobalRef> = OnceLock::new();

/// Check if state matches the given flag
pub fn is_state(state: u8) -> bool {
    STATE.load(Ordering::SeqCst) == state
}

/// Change state
pub fn set_state(state: u8) {
    STATE.store(state, Ordering::SeqCst);
}

/// Get current state
pub fn get_state() -> u8 {
    STATE.load(Ordering::SeqCst)
}

/// Helper to check if initialized (any state except 0)
pub fn is_initialized() -> bool {
    get_state() != STATE_INIT || STORAGE_WITH_DATA.get().is_some()
}

/// Helper to check if running
pub fn is_running() -> bool {
    is_state(STATE_RUNNING)
}

/// Helper to check if stopped
pub fn is_stopped() -> bool {
    is_state(STATE_STOPPED)
}
