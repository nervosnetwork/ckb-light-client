//! Query APIs for JNI bridge
//!
//! Provides 17 query APIs matching WASM implementation.
//! All functions return JSON strings for complex types, or null on error.

use super::types::*;
use crate::service::{
    Cell, CellsCapacity, FetchStatus, LocalNode, Order, Pagination, RemoteNode, SearchKey,
    SetScriptsCommand, TransactionWithStatus,
};
use crate::storage::{self, extract_raw_data, Key, KeyPrefix, LAST_STATE_KEY};
use crate::verify::verify_tx;
use ckb_jsonrpc_types::{BlockView, EstimateCycles, HeaderView, JsonBytes, Transaction};
use ckb_network::extract_peer_id;
use ckb_systemtime::unix_time_as_millis;
use ckb_traits::HeaderProvider;
use ckb_types::{core, packed, prelude::*, H256};
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;
use log::{debug, error, warn};
use std::ptr;
use std::str::FromStr;

/// Helper to check running state and return null if not running
macro_rules! check_running {
    ($env:expr) => {
        if !is_running() {
            warn!("Light client not running, current state: {}", get_state());
            return ptr::null_mut();
        }
    };
}

/// Helper to create JString from serde result
fn to_jstring<T: serde::Serialize>(env: &mut JNIEnv, value: &T) -> jstring {
    match serde_json::to_string(value) {
        Ok(json) => match env.new_string(json) {
            Ok(s) => s.into_raw(),
            Err(e) => {
                error!("Failed to create JString: {}", e);
                ptr::null_mut()
            }
        },
        Err(e) => {
            error!("Failed to serialize to JSON: {}", e);
            ptr::null_mut()
        }
    }
}

/// Get tip header
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeGetTipHeader(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    check_running!(env);

    let swc = match STORAGE_WITH_DATA.get() {
        Some(s) => s,
        None => {
            error!("Storage not initialized");
            return ptr::null_mut();
        }
    };

    let tip_header = swc.storage().get_tip_header();
    let header_view: HeaderView = tip_header.into_view().into();

    to_jstring(&mut env, &header_view)
}

/// Get genesis block
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeGetGenesisBlock(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    check_running!(env);

    let swc = match STORAGE_WITH_DATA.get() {
        Some(s) => s,
        None => {
            error!("Storage not initialized");
            return ptr::null_mut();
        }
    };

    let genesis_block = swc.storage().get_genesis_block();

    // Convert packed::Block to BlockView via core::BlockView
    use ckb_types::prelude::Unpack;
    let core_block_view: ckb_types::core::BlockView = genesis_block.into_view();
    let block_view: BlockView = core_block_view.into();
    to_jstring(&mut env, &block_view)
}

/// Get header by hash
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeGetHeader(
    mut env: JNIEnv,
    _class: JClass,
    hash: JString,
) -> jstring {
    check_running!(env);

    let hash_str: String = match env.get_string(&hash) {
        Ok(s) => s.into(),
        Err(e) => {
            error!("Failed to get hash string: {}", e);
            return ptr::null_mut();
        }
    };

    let swc = match STORAGE_WITH_DATA.get() {
        Some(s) => s,
        None => {
            error!("Storage not initialized");
            return ptr::null_mut();
        }
    };

    let h256 = match H256::from_str(&hash_str) {
        Ok(h) => h,
        Err(e) => {
            error!("Invalid hash: {}", e);
            return ptr::null_mut();
        }
    };

    let hash = packed::Byte32::from_slice(h256.as_bytes()).expect("H256 to Byte32");

    match swc.storage().get_header(&hash) {
        Some(header) => {
            let header_view: HeaderView = header.into();
            to_jstring(&mut env, &header_view)
        }
        None => ptr::null_mut(),
    }
}

/// Fetch header (with fetch status)
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeFetchHeader(
    mut env: JNIEnv,
    _class: JClass,
    hash: JString,
) -> jstring {
    check_running!(env);

    let hash_str: String = match env.get_string(&hash) {
        Ok(s) => s.into(),
        Err(e) => {
            error!("Failed to get hash string: {}", e);
            return ptr::null_mut();
        }
    };

    let swc = match STORAGE_WITH_DATA.get() {
        Some(s) => s,
        None => {
            error!("Storage not initialized");
            return ptr::null_mut();
        }
    };

    let peers = match PEERS.get() {
        Some(p) => p,
        None => {
            error!("Peers not initialized");
            return ptr::null_mut();
        }
    };

    let h256 = match H256::from_str(&hash_str) {
        Ok(h) => h,
        Err(e) => {
            error!("Invalid hash: {}", e);
            return ptr::null_mut();
        }
    };

    let hash = packed::Byte32::from_slice(h256.as_bytes()).expect("H256 to Byte32");

    let fetch_status: FetchStatus<HeaderView> =
        if let Some(header) = swc.storage().get_header(&hash) {
            FetchStatus::Fetched {
                data: header.into(),
            }
        } else if peers.fetching_headers().contains_key(&hash) {
            FetchStatus::Fetching {
                first_sent: 0.into(),
            }
        } else {
            // Add to fetch queue
            let _net_controller = match NET_CONTROL.get() {
                Some(nc) => nc,
                None => {
                    error!("Network controller not initialized");
                    return ptr::null_mut();
                }
            };

            let timestamp = unix_time_as_millis();
            peers.add_fetch_header(hash.clone(), timestamp);

            FetchStatus::Added {
                timestamp: timestamp.into(),
            }
        };

    to_jstring(&mut env, &fetch_status)
}

/// Set scripts
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeSetScripts(
    mut env: JNIEnv,
    _class: JClass,
    scripts_json: JString,
    command: i32,
) -> jni::sys::jboolean {
    if !is_running() {
        warn!("Light client not running");
        return jni::sys::JNI_FALSE;
    }

    let scripts_str: String = match env.get_string(&scripts_json) {
        Ok(s) => s.into(),
        Err(e) => {
            error!("Failed to get scripts JSON: {}", e);
            return jni::sys::JNI_FALSE;
        }
    };

    let scripts_json: Vec<crate::service::ScriptStatus> = match serde_json::from_str(&scripts_str) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to parse scripts JSON: {}", e);
            return jni::sys::JNI_FALSE;
        }
    };

    // Convert service::ScriptStatus to storage::ScriptStatus
    let scripts: Vec<storage::ScriptStatus> = scripts_json
        .into_iter()
        .map(|s| storage::ScriptStatus {
            script: s.script.into(),
            script_type: match s.script_type {
                crate::service::ScriptType::Lock => storage::ScriptType::Lock,
                crate::service::ScriptType::Type => storage::ScriptType::Type,
            },
            block_number: s.block_number.into(),
        })
        .collect();

    let cmd = match command {
        0 => SetScriptsCommand::All,
        1 => SetScriptsCommand::Partial,
        2 => SetScriptsCommand::Delete,
        _ => {
            error!("Invalid command: {}", command);
            return jni::sys::JNI_FALSE;
        }
    };

    let swc = match STORAGE_WITH_DATA.get() {
        Some(s) => s,
        None => {
            error!("Storage not initialized");
            return jni::sys::JNI_FALSE;
        }
    };

    swc.storage().update_filter_scripts(scripts, cmd.into());

    // Clear matched blocks when scripts change
    let peers = match PEERS.get() {
        Some(p) => p,
        None => {
            error!("Peers not initialized");
            return jni::sys::JNI_FALSE;
        }
    };

    // Lock matched_blocks and clear them
    let mut matched_blocks = peers.matched_blocks().blocking_write();
    peers.clear_matched_blocks(&mut matched_blocks);

    jni::sys::JNI_TRUE
}

/// Get scripts
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeGetScripts(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    check_running!(env);

    let swc = match STORAGE_WITH_DATA.get() {
        Some(s) => s,
        None => {
            error!("Storage not initialized");
            return ptr::null_mut();
        }
    };

    let scripts = swc.storage().get_filter_scripts();
    // Convert storage::ScriptStatus to service::ScriptStatus for serialization
    let scripts: Vec<crate::service::ScriptStatus> = scripts
        .into_iter()
        .map(|s| crate::service::ScriptStatus {
            script: s.script.into(),
            script_type: match s.script_type {
                storage::ScriptType::Lock => crate::service::ScriptType::Lock,
                storage::ScriptType::Type => crate::service::ScriptType::Type,
            },
            block_number: s.block_number.into(),
        })
        .collect();
    to_jstring(&mut env, &scripts)
}

/// Get local node info
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeLocalNodeInfo(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    check_running!(env);

    let net_controller = match NET_CONTROL.get() {
        Some(nc) => nc,
        None => {
            error!("Network controller not initialized");
            return ptr::null_mut();
        }
    };

    let _consensus = match CONSENSUS.get() {
        Some(c) => c,
        None => {
            error!("Consensus not initialized");
            return ptr::null_mut();
        }
    };

    let node_id = net_controller.node_id();

    let node_info = LocalNode {
        active: is_running(),
        addresses: vec![], // TODO: get actual addresses
        connections: (net_controller.connected_peers().len() as u64).into(),
        node_id,
        protocols: vec![], // TODO: get actual protocols
        version: env!("CARGO_PKG_VERSION").to_owned(),
    };

    to_jstring(&mut env, &node_info)
}

/// Get peers
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeGetPeers(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    check_running!(env);

    let net_controller = match NET_CONTROL.get() {
        Some(nc) => nc,
        None => {
            error!("Network controller not initialized");
            return ptr::null_mut();
        }
    };

    let mut remote_nodes = Vec::new();

    // connected_peers() returns Vec<(SessionId, Peer)>
    for (_session_id, peer) in net_controller.connected_peers() {
        // Extract peer_id from the connected address
        let node_id = extract_peer_id(&peer.connected_addr)
            .map(|id| id.to_base58())
            .unwrap_or_else(|| "unknown".to_owned());

        // Calculate connection duration in milliseconds
        let connected_duration_ms = peer.connected_time.elapsed().as_millis() as u64;

        let remote_node = RemoteNode {
            version: peer
                .identify_info
                .as_ref()
                .map(|info| info.client_version.clone())
                .unwrap_or_else(|| "unknown".to_owned()),
            node_id,
            addresses: vec![], // TODO: get actual addresses
            connected_duration: connected_duration_ms.into(),
            sync_state: None,  // TODO: get sync state
            protocols: vec![], // TODO: get actual protocols
        };

        remote_nodes.push(remote_node);
    }

    to_jstring(&mut env, &remote_nodes)
}

// TODO: Implement remaining 10 APIs:
// - nativeGetCells
// - nativeGetTransactions
// - nativeGetCellsCapacity
// - nativeSendTransaction
// - nativeGetTransaction
// - nativeFetchTransaction
// - nativeEstimateCycles
// (Plus the 3 already implemented: GetTipHeader, GetGenesisBlock, GetHeader, FetchHeader,
// SetScripts, GetScripts, LocalNodeInfo, GetPeers)

// Placeholder implementations for remaining APIs
// These return null for now and can be implemented as needed

#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeGetCells(
    _env: JNIEnv,
    _class: JClass,
    _search_key_json: JString,
    _order: JString,
    _limit: jni::sys::jint,
    _cursor: JString,
) -> jstring {
    // TODO: Implement
    warn!("nativeGetCells not yet implemented");
    ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeGetTransactions(
    _env: JNIEnv,
    _class: JClass,
    _search_key_json: JString,
    _order: JString,
    _limit: jni::sys::jint,
    _cursor: JString,
) -> jstring {
    // TODO: Implement
    warn!("nativeGetTransactions not yet implemented");
    ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeGetCellsCapacity(
    _env: JNIEnv,
    _class: JClass,
    _search_key_json: JString,
) -> jstring {
    // TODO: Implement
    warn!("nativeGetCellsCapacity not yet implemented");
    ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeSendTransaction(
    _env: JNIEnv,
    _class: JClass,
    _tx_json: JString,
) -> jstring {
    // TODO: Implement
    warn!("nativeSendTransaction not yet implemented");
    ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeGetTransaction(
    _env: JNIEnv,
    _class: JClass,
    _hash: JString,
) -> jstring {
    // TODO: Implement
    warn!("nativeGetTransaction not yet implemented");
    ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeFetchTransaction(
    _env: JNIEnv,
    _class: JClass,
    _hash: JString,
) -> jstring {
    // TODO: Implement
    warn!("nativeFetchTransaction not yet implemented");
    ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeEstimateCycles(
    _env: JNIEnv,
    _class: JClass,
    _tx_json: JString,
) -> jstring {
    // TODO: Implement
    warn!("nativeEstimateCycles not yet implemented");
    ptr::null_mut()
}
