//! Lifecycle management for JNI bridge
//!
//! Implements init/start/stop/status functions that mirror light-client-bin/src/subcmds.rs

use super::callbacks::{flush_logs, invoke_status_callback, JniLogger};
use super::types::*;
use crate::runtime::StartedLightClient;
use crate::types::RunEnv;
use ckb_async_runtime::tokio;
use ckb_stop_handler::{broadcast_exit_signals, wait_all_ckb_services_exit};
use jni::objects::{JClass, JObject, JString};
use jni::sys::{jboolean, jint, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use log::{error, info, warn};
use std::fs;

/// JNI: Initialize the light client
///
/// This performs all initialization including:
/// - Loading TOML config
/// - Initializing Storage and ChainSpec
/// - Creating protocols (Sync, Relay, LightClient, Filter)
/// - Starting NetworkService
/// - Starting RPC server
/// - Creating tokio runtime in dedicated thread
///
/// Note: This starts the network service but doesn't change state to RUNNING yet.
/// Call nativeStart() to actually start processing.
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeInit(
    mut env: JNIEnv,
    _class: JClass,
    config_path_jstr: JString,
    log_callback: JObject,
    status_callback: JObject,
) -> jboolean {
    // Check if already initialized
    if is_initialized() {
        error!("Already initialized!");
        return JNI_FALSE;
    }

    // Initialize JavaVM and callbacks only once (first time)
    if JAVA_VM.get().is_none() {
        info!("First time initialization - setting up JavaVM and callbacks...");

        // Get JavaVM for callbacks
        let vm = match env.get_java_vm() {
            Ok(vm) => vm,
            Err(e) => {
                eprintln!("Failed to get JavaVM: {}", e);
                return JNI_FALSE;
            }
        };

        // Store JavaVM
        if JAVA_VM.set(vm).is_err() {
            error!("Failed to store JavaVM");
            return JNI_FALSE;
        }

        // Create global refs for callbacks
        let log_callback_ref = match env.new_global_ref(log_callback) {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to create log callback GlobalRef: {}", e);
                return JNI_FALSE;
            }
        };

        let status_callback_ref = match env.new_global_ref(status_callback) {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to create status callback GlobalRef: {}", e);
                return JNI_FALSE;
            }
        };

        // Store callbacks
        if LOG_CALLBACK.set(log_callback_ref).is_err() {
            error!("Failed to store log callback");
            return JNI_FALSE;
        }

        if STATUS_CALLBACK.set(status_callback_ref).is_err() {
            error!("Failed to store status callback");
            return JNI_FALSE;
        }

        // Initialize logger with JNI logger
        if let Err(e) = log::set_boxed_logger(Box::new(JniLogger)) {
            eprintln!("Failed to set logger: {}", e);
            return JNI_FALSE;
        }
        // Default to debug; filters can still be tightened via nativeSetLogFilter()
        log::set_max_level(log::LevelFilter::Trace);
    } else {
        info!("Reinitialization - JavaVM and callbacks already set, skipping...")
    }

    info!("Starting CKB Light Client JNI initialization...");

    // Get config path
    let config_path: String = match env.get_string(&config_path_jstr) {
        Ok(s) => s.into(),
        Err(e) => {
            error!("Failed to get config path: {}", e);
            return JNI_FALSE;
        }
    };

    info!("Loading config from: {}", config_path);

    // Load and parse TOML config
    let run_env: RunEnv = match load_config(&config_path) {
        Ok(env) => env,
        Err(e) => {
            error!("Failed to load config: {}", e);
            return JNI_FALSE;
        }
    };

    info!("Config loaded successfully");
    info!("Chain: {}", run_env.chain);
    info!("Store path: {:?}", run_env.store.path);
    info!("Network path: {:?}", run_env.network.path);

    let client = match StartedLightClient::start(run_env) {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to start light client: {}", e);
            return JNI_FALSE;
        }
    };

    // Store global state for queries and shutdown
    *STORAGE_WITH_DATA.write().unwrap() = Some(client.storage_with_data());
    *NET_CONTROL.write().unwrap() = Some(client.network_controller());
    *CONSENSUS.write().unwrap() = Some(client.consensus());
    *PEERS.write().unwrap() = Some(client.peers());
    *CLIENT_HANDLE.lock().unwrap() = Some(client);

    // Set state to INIT
    set_state(STATE_INIT);

    info!("CKB Light Client initialized successfully!");

    // Notify status callback
    let _ = invoke_status_callback("initialized", "");

    JNI_TRUE
}

/// Load config from TOML file
fn load_config(path: &str) -> Result<RunEnv, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let run_env: RunEnv = toml::from_str(&content)?;
    Ok(run_env)
}

/// JNI: Start the light client
///
/// This transitions from INIT to RUNNING state.
/// The network service is already running (started in init).
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeStart(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    // Check if initialized
    if !is_state(STATE_INIT) {
        error!("Not in INIT state! Current state: {}", get_state());
        return JNI_FALSE;
    }

    info!("Starting CKB Light Client...");

    // Transition to RUNNING
    set_state(STATE_RUNNING);

    info!("CKB Light Client started successfully!");

    // Notify status callback
    let _ = invoke_status_callback("running", "");

    JNI_TRUE
}

/// JNI: Stop the light client
///
/// This fully shuts down the light client:
/// - Broadcast exit signals to all services
/// - Wait for services to stop
/// - Clear all global state
/// - Flush logs
/// - Transition to STOPPED state
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeStop(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    // Check if running
    if !is_state(STATE_RUNNING) {
        warn!("Not in RUNNING state! Current state: {}", get_state());
        return JNI_FALSE;
    }

    info!("Stopping CKB Light Client...");

    // Take ownership of the running client (releases the mutex before blocking waits)
    let client_opt = {
        let mut guard = CLIENT_HANDLE.lock().unwrap();
        guard.take()
    };
    let mut client: StartedLightClient = match client_opt {
        Some(client) => client,
        None => {
            warn!("Stop requested but no client handle found");
            return JNI_FALSE;
        }
    };

    // Broadcast exit signals to all services
    broadcast_exit_signals();

    // Wait for all CKB services to exit
    info!("Waiting for services to exit...");
    wait_all_ckb_services_exit();

    // Release runtime guard and wait for runtime tasks to finish
    client.runtime_handle().drop_guard();
    tokio::task::block_in_place(|| {
        client.stop_receiver().blocking_recv();
    });

    // Flush any pending logs
    flush_logs();

    // Clear all global state (RwLock values)
    clear_state();

    // Transition to STOPPED
    set_state(STATE_STOPPED);

    info!("CKB Light Client stopped successfully!");

    // Notify status callback
    let _ = invoke_status_callback("stopped", "");

    JNI_TRUE
}

/// JNI: Get current status
///
/// Returns:
/// - 0 (INIT): Initialized but not started
/// - 1 (RUNNING): Running
/// - 2 (STOPPED): Stopped
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeGetStatus(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    get_state() as jint
}

/// JNI: Set log filter using RUST_LOG format
///
/// Parameters:
/// - filter_str: RUST_LOG-style filter string
///   Examples:
///   - "info" - all modules at info level
///   - "debug" - all modules at debug level
///   - "info,ckb_network=debug" - most at info, ckb_network at debug
///   - "info,ckb_network=debug,ckb_sync=trace" - per-module levels
///
/// Returns true if successful, false otherwise
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeSetLogFilter(
    mut env: JNIEnv,
    _class: JClass,
    filter_jstr: JString,
) -> jboolean {
    // Get filter string
    let filter_str: String = match env.get_string(&filter_jstr) {
        Ok(s) => s.into(),
        Err(e) => {
            error!("Failed to get filter string: {}", e);
            return JNI_FALSE;
        }
    };

    info!("Setting log filter to: {}", filter_str);
    super::callbacks::set_log_filter(&filter_str);

    JNI_TRUE
}
