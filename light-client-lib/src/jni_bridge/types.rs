//! Global state management for JNI bridge
//!
//! Uses RwLock<Option<T>> for resettable state, OnceLock for permanent state.

use crate::protocols::Peers;
use crate::runtime::StartedLightClient;
use crate::storage::StorageWithChainData;
use crate::types::Mutex;
use ckb_chain_spec::consensus::Consensus;
use ckb_network::NetworkController;
use jni::objects::GlobalRef;
use jni::JavaVM;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use tokio::runtime::Runtime;

/// State machine values
/// - 0 (INIT): Not initialized
/// - 1 (RUNNING): Running
/// - 2 (STOPPED): Stopped
pub static STATE: AtomicU8 = AtomicU8::new(0);

pub const STATE_INIT: u8 = 0;
pub const STATE_RUNNING: u8 = 1;
pub const STATE_STOPPED: u8 = 2;

/// Global storage with chain data (resettable)
pub static STORAGE_WITH_DATA: RwLock<Option<StorageWithChainData>> = RwLock::new(None);

/// Global network controller (resettable)
pub static NET_CONTROL: RwLock<Option<NetworkController>> = RwLock::new(None);

/// Global consensus (resettable)
pub static CONSENSUS: RwLock<Option<Arc<Consensus>>> = RwLock::new(None);

/// Global peers manager (resettable)
pub static PEERS: RwLock<Option<Arc<Peers>>> = RwLock::new(None);

/// Global tokio runtime (resettable)
pub static RUNTIME: RwLock<Option<Runtime>> = RwLock::new(None);

/// Global JavaVM for callbacks (permanent, set once)
pub static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();

/// Global log callback (permanent, set once)
pub static LOG_CALLBACK: OnceLock<GlobalRef> = OnceLock::new();

/// Global status callback (permanent, set once)
pub static STATUS_CALLBACK: OnceLock<GlobalRef> = OnceLock::new();

/// Global handle to the running light client (keeps runtime alive)
pub static CLIENT_HANDLE: Mutex<Option<StartedLightClient>> = Mutex::new(None);

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

/// Helper to check if initialized
pub fn is_initialized() -> bool {
    STORAGE_WITH_DATA.read().unwrap().is_some()
}

/// Helper to check if running
pub fn is_running() -> bool {
    is_state(STATE_RUNNING)
}

/// Helper to check if stopped
pub fn is_stopped() -> bool {
    is_state(STATE_STOPPED)
}

/// Clear all resettable global state for full shutdown
pub fn clear_state() {
    *CLIENT_HANDLE.lock().unwrap() = None;
    *STORAGE_WITH_DATA.write().unwrap() = None;
    *NET_CONTROL.write().unwrap() = None;
    *CONSENSUS.write().unwrap() = None;
    *PEERS.write().unwrap() = None;
    *RUNTIME.write().unwrap() = None;
}
