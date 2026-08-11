//! Global state management for JNI bridge
//!
//! Uses OnceLock for process-lifetime state (JavaVM) and Mutex<Option<T>> for
//! session-lifetime state that can be reset on stop to allow re-initialization.

use crate::protocols::Peers;
use crate::service::{LightClientChainService, LightClientNetworkService, LightClientService};
use crate::storage::{Storage, StorageWithChainData};
use ckb_chain_spec::consensus::Consensus;
use ckb_network::NetworkController;
use jni::objects::GlobalRef;
use jni::JavaVM;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::runtime::Runtime;

/// State machine values
/// - 0 (INIT): Not initialized, or cleaned up after stop
/// - 1 (RUNNING): Running
/// - 2 (STOPPED): Stopped (transient, reset to INIT after cleanup)
pub static STATE: AtomicU8 = AtomicU8::new(0);

pub const STATE_INIT: u8 = 0;
pub const STATE_RUNNING: u8 = 1;
pub const STATE_STOPPED: u8 = 2;

// --- Process-lifetime state (set once, never reset) ---

/// Global JavaVM — one per process, never changes
pub static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();

// --- Session-lifetime state (set on init, cleared on stop) ---

/// Global status callback
pub static STATUS_CALLBACK: Mutex<Option<GlobalRef>> = Mutex::new(None);

/// Global storage with chain data
pub static STORAGE_WITH_DATA: Mutex<Option<StorageWithChainData>> = Mutex::new(None);

/// Global network controller
pub static NET_CONTROL: Mutex<Option<NetworkController>> = Mutex::new(None);

/// Global consensus
pub static CONSENSUS: Mutex<Option<Arc<Consensus>>> = Mutex::new(None);

/// Global peers manager
pub static PEERS: Mutex<Option<Arc<Peers>>> = Mutex::new(None);

/// Global tokio runtime (kept alive to run background tasks)
pub static RUNTIME: Mutex<Option<Runtime>> = Mutex::new(None);

/// Clear all session-lifetime state, allowing re-initialization.
/// Called from nativeStop() after services have been shut down.
pub fn reset_session_state() {
    // Drop in reverse order of initialization
    *STORAGE_WITH_DATA.lock().expect("lock poisoned") = None;
    *NET_CONTROL.lock().expect("lock poisoned") = None;
    *PEERS.lock().expect("lock poisoned") = None;
    *CONSENSUS.lock().expect("lock poisoned") = None;
    *RUNTIME.lock().expect("lock poisoned") = None;
    *STATUS_CALLBACK.lock().expect("lock poisoned") = None;
    set_state(STATE_INIT);
}

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

/// Helper to check if initialized (session state is present)
pub fn is_initialized() -> bool {
    get_state() != STATE_INIT
        || STORAGE_WITH_DATA
            .lock()
            .ok()
            .map_or(false, |g| g.is_some())
}

/// Helper to check if running
pub fn is_running() -> bool {
    is_state(STATE_RUNNING)
}

/// Helper to check if stopped
pub fn is_stopped() -> bool {
    is_state(STATE_STOPPED)
}

/// Create a LightClientService instance from global state
pub fn cell_service() -> Option<LightClientService<Storage>> {
    let guard = STORAGE_WITH_DATA.lock().ok()?;
    let swc = guard.as_ref()?;
    Some(LightClientService::new(Arc::new(swc.storage().clone())))
}

/// Create a LightClientChainService instance from global state
pub fn chain_service() -> Option<LightClientChainService> {
    let swc = STORAGE_WITH_DATA.lock().ok()?.as_ref()?.clone();
    let consensus = CONSENSUS.lock().ok()?.as_ref()?.clone();
    Some(LightClientChainService::new(swc, consensus))
}

/// Create a LightClientNetworkService instance from global state
pub fn network_service() -> Option<LightClientNetworkService> {
    let nc = NET_CONTROL.lock().ok()?.as_ref()?.clone();
    let peers = PEERS.lock().ok()?.as_ref()?.clone();
    Some(LightClientNetworkService::new(nc, peers))
}
