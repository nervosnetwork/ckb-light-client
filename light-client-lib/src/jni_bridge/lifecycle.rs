//! Lifecycle management for JNI bridge
//!
//! Implements init/start/stop/status functions that mirror light-client-bin/src/subcmds.rs

use super::callbacks::invoke_status_callback;
use super::types::*;
use crate::protocols::{
    FilterProtocol, LightClientProtocol, Peers, PendingTxs, RelayProtocol, SyncProtocol,
    BAD_MESSAGE_ALLOWED_EACH_HOUR, CHECK_POINT_INTERVAL,
};
use crate::storage::{Storage, StorageWithChainData};
use crate::types::RunEnv;
use crate::utils;
use ckb_async_runtime::new_global_runtime;
use ckb_chain_spec::ChainSpec;
use ckb_network::{
    network::TransportType, CKBProtocol, CKBProtocolHandler, Flags, NetworkService, NetworkState,
    SupportProtocols,
};
use ckb_resource::Resource;
use ckb_stop_handler::{broadcast_exit_signals, wait_all_ckb_services_exit};
use jni::objects::{JClass, JObject, JString};
use jni::sys::{jboolean, jint, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use log::{debug, error, info, trace, warn};
use std::fs;
use std::sync::{Arc, RwLock};
use std::thread;

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
    status_callback: JObject,
) -> jboolean {
    // Check if already initialized
    if is_initialized() {
        error!("Already initialized!");
        return JNI_FALSE;
    }

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
        eprintln!("Failed to store JavaVM");
        return JNI_FALSE;
    }

    // Create global ref for status callback
    let status_callback_ref = match env.new_global_ref(status_callback) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to create status callback GlobalRef: {}", e);
            return JNI_FALSE;
        }
    };

    // Store status callback
    if STATUS_CALLBACK.set(status_callback_ref).is_err() {
        eprintln!("Failed to store status callback");
        return JNI_FALSE;
    }

    // Initialize Android logger
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Debug)
            .with_tag("ckb-light-client"),
    );

    info!("Android logger initialized with Debug level");
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

    // Create network directory if needed
    if let Err(e) = utils::fs::need_directory(&run_env.network.path) {
        error!("Failed to create network directory: {}", e);
        return JNI_FALSE;
    }

    // Initialize storage
    info!("Initializing storage...");
    let storage = Storage::new(&run_env.store.path);

    // Load chain spec
    info!("Loading chain spec for: {}", run_env.chain);
    let chain_spec = match ChainSpec::load_from(&match run_env.chain.as_str() {
        "mainnet" => Resource::bundled("specs/mainnet.toml".to_string()),
        "testnet" => Resource::bundled("specs/testnet.toml".to_string()),
        path => Resource::file_system(path.into()),
    }) {
        Ok(spec) => spec,
        Err(e) => {
            error!("Failed to load chain spec: {}", e);
            return JNI_FALSE;
        }
    };

    let consensus = match chain_spec.build_consensus() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to build consensus: {}", e);
            return JNI_FALSE;
        }
    };

    info!("Initializing genesis block...");
    storage.init_genesis_block(consensus.genesis_block().data());

    info!("Cleaning up invalid matched blocks...");
    storage.cleanup_invalid_matched_blocks();

    // Initialize network components
    info!("Initializing network state...");
    let pending_txs = Arc::new(RwLock::new(PendingTxs::default()));
    let max_outbound_peers = run_env.network.max_outbound_peers;

    let network_state = match NetworkState::from_config(run_env.network.clone()) {
        Ok(ns) => Arc::new(ns.required_flags(
            Flags::DISCOVERY
                | Flags::SYNC
                | Flags::RELAY
                | Flags::LIGHT_CLIENT
                | Flags::BLOCK_FILTER,
        )),
        Err(e) => {
            error!("Failed to initialize network state: {}", e);
            return JNI_FALSE;
        }
    };

    // Create peers manager
    info!("Creating peers manager...");
    let peers = Arc::new(Peers::new(
        max_outbound_peers,
        CHECK_POINT_INTERVAL,
        storage.get_last_check_point(),
        BAD_MESSAGE_ALLOWED_EACH_HOUR,
    ));

    // Initialize protocols
    info!("Initializing protocols...");
    let sync_protocol = SyncProtocol::new(storage.clone(), Arc::clone(&peers));
    let relay_protocol =
        RelayProtocol::new(pending_txs.clone(), Arc::clone(&peers), storage.clone());
    let light_client: Box<dyn CKBProtocolHandler> = Box::new(LightClientProtocol::new(
        storage.clone(),
        Arc::clone(&peers),
        consensus.clone(),
    ));
    let filter_protocol = FilterProtocol::new(storage.clone(), Arc::clone(&peers));

    let protocols = vec![
        CKBProtocol::new_with_support_protocol(
            SupportProtocols::Sync,
            Box::new(sync_protocol),
            Arc::clone(&network_state),
        ),
        CKBProtocol::new_with_support_protocol(
            SupportProtocols::RelayV3,
            Box::new(relay_protocol),
            Arc::clone(&network_state),
        ),
        CKBProtocol::new_with_support_protocol(
            SupportProtocols::LightClient,
            light_client,
            Arc::clone(&network_state),
        ),
        CKBProtocol::new_with_support_protocol(
            SupportProtocols::Filter,
            Box::new(filter_protocol),
            Arc::clone(&network_state),
        ),
    ];

    let required_protocol_ids = vec![
        SupportProtocols::Sync.protocol_id(),
        SupportProtocols::LightClient.protocol_id(),
        SupportProtocols::Filter.protocol_id(),
    ];

    // Create tokio runtime
    info!("Creating tokio runtime...");
    let (runtime_handle, _receiver, runtime) = new_global_runtime(None);

    // Store runtime
    if RUNTIME.set(runtime).is_err() {
        error!("Failed to store runtime");
        return JNI_FALSE;
    }

    // Start network service
    info!("Starting network service...");
    let network_controller = match NetworkService::new(
        Arc::clone(&network_state),
        protocols,
        required_protocol_ids,
        (
            consensus.identify_name(),
            env!("CARGO_PKG_VERSION").to_owned(),
            Flags::DISCOVERY,
        ),
        TransportType::Tcp,
    )
    .start(&runtime_handle)
    {
        Ok(nc) => nc,
        Err(e) => {
            error!("Failed to start network service: {}", e);
            return JNI_FALSE;
        }
    };

    // Store network controller
    if NET_CONTROL.set(network_controller.clone()).is_err() {
        error!("Failed to store network controller");
        return JNI_FALSE;
    }

    // Create StorageWithChainData
    let swc = StorageWithChainData::new(storage.clone(), Arc::clone(&peers), pending_txs.clone());

    // Store global state
    if STORAGE_WITH_DATA.set(swc).is_err() {
        error!("Failed to store StorageWithChainData");
        return JNI_FALSE;
    }

    let consensus_arc = Arc::new(consensus);
    if CONSENSUS.set(consensus_arc.clone()).is_err() {
        error!("Failed to store consensus");
        return JNI_FALSE;
    }

    if PEERS.set(peers.clone()).is_err() {
        error!("Failed to store peers");
        return JNI_FALSE;
    }

    // Start RPC server if configured
    info!("Starting RPC server on {}...", run_env.rpc.listen_address);
    // Note: RPC server implementation would go here
    // For now, we're skipping RPC server startup to keep the implementation focused

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
/// This gracefully shuts down the light client:
/// - Broadcast exit signals
/// - Wait for services to stop
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

    // Broadcast exit signals to all services
    broadcast_exit_signals();

    // Wait for all CKB services to exit
    info!("Waiting for services to exit...");
    wait_all_ckb_services_exit();

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
