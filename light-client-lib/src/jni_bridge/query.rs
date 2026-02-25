//! Query APIs for JNI bridge
//!
//! Provides query APIs matching WASM implementation, delegating to the unified service layer.
//! All functions return JSON strings for complex types, or null on error.

use super::types::*;
use crate::service::{Order, SearchKey, SetScriptsCommand};
use ckb_jsonrpc_types::{JsonBytes, Transaction, Uint32};
use ckb_types::H256;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;
use log::{error, warn};
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

/// Helper to get a String from JString, returning null on error
fn get_jstring(env: &mut JNIEnv, s: &JString) -> Option<String> {
    match env.get_string(s) {
        Ok(s) => Some(s.into()),
        Err(e) => {
            error!("Failed to get JString: {}", e);
            None
        }
    }
}

const MAX_ADDRS: usize = 50;

/// Get tip header
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeGetTipHeader(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    check_running!(env);
    let service = match chain_service() {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    to_jstring(&mut env, &service.get_tip_header())
}

/// Get genesis block
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeGetGenesisBlock(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    check_running!(env);
    let service = match chain_service() {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    to_jstring(&mut env, &service.get_genesis_block())
}

/// Get header by hash
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeGetHeader(
    mut env: JNIEnv,
    _class: JClass,
    hash: JString,
) -> jstring {
    check_running!(env);
    let hash_str = match get_jstring(&mut env, &hash) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    let h256 = match H256::from_str(&hash_str) {
        Ok(h) => h,
        Err(e) => {
            error!("Invalid hash: {}", e);
            return ptr::null_mut();
        }
    };
    let service = match chain_service() {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    match service.get_header(&h256) {
        Some(header) => to_jstring(&mut env, &header),
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
    let hash_str = match get_jstring(&mut env, &hash) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    let h256 = match H256::from_str(&hash_str) {
        Ok(h) => h,
        Err(e) => {
            error!("Invalid hash: {}", e);
            return ptr::null_mut();
        }
    };
    let service = match chain_service() {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    to_jstring(&mut env, &service.fetch_header(&h256))
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

    let scripts_str = match get_jstring(&mut env, &scripts_json) {
        Some(s) => s,
        None => return jni::sys::JNI_FALSE,
    };

    let scripts: Vec<crate::service::ScriptStatus> = match serde_json::from_str(&scripts_str) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to parse scripts JSON: {}", e);
            return jni::sys::JNI_FALSE;
        }
    };

    let cmd = match command {
        0 => SetScriptsCommand::All,
        1 => SetScriptsCommand::Partial,
        2 => SetScriptsCommand::Delete,
        _ => {
            error!("Invalid command: {}", command);
            return jni::sys::JNI_FALSE;
        }
    };

    let service = match chain_service() {
        Some(s) => s,
        None => return jni::sys::JNI_FALSE,
    };

    service.set_scripts(scripts, Some(cmd));
    jni::sys::JNI_TRUE
}

/// Get scripts
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeGetScripts(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    check_running!(env);
    let service = match chain_service() {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    to_jstring(&mut env, &service.get_scripts())
}

/// Get local node info
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeLocalNodeInfo(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    check_running!(env);
    let service = match network_service() {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    to_jstring(&mut env, &service.local_node_info(MAX_ADDRS))
}

/// Get peers
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeGetPeers(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    check_running!(env);
    let service = match network_service() {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    to_jstring(&mut env, &service.get_peers())
}

/// Get cells
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeGetCells(
    mut env: JNIEnv,
    _class: JClass,
    search_key_json: JString,
    order: JString,
    limit: jni::sys::jint,
    cursor: JString,
) -> jstring {
    check_running!(env);

    let search_key_str = match get_jstring(&mut env, &search_key_json) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    let search_key: SearchKey = match serde_json::from_str(&search_key_str) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to parse search_key: {}", e);
            return ptr::null_mut();
        }
    };

    let order_str = match get_jstring(&mut env, &order) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    let order: Order = match serde_json::from_str(&format!("\"{}\"", order_str)) {
        Ok(o) => o,
        Err(e) => {
            error!("Failed to parse order: {}", e);
            return ptr::null_mut();
        }
    };

    let after_cursor = if env.is_same_object(&cursor, JString::default()).unwrap_or(true) {
        None
    } else {
        get_jstring(&mut env, &cursor).and_then(|s| {
            if s.is_empty() {
                None
            } else {
                serde_json::from_str(&format!("\"{}\"", s)).ok()
            }
        })
    };

    let service = match cell_service() {
        Some(s) => s,
        None => return ptr::null_mut(),
    };

    match service.get_cells(search_key, order, Uint32::from(limit as u32), after_cursor) {
        Ok(result) => to_jstring(&mut env, &result),
        Err(e) => {
            error!("get_cells failed: {}", e);
            ptr::null_mut()
        }
    }
}

/// Get transactions
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeGetTransactions(
    mut env: JNIEnv,
    _class: JClass,
    search_key_json: JString,
    order: JString,
    limit: jni::sys::jint,
    cursor: JString,
) -> jstring {
    check_running!(env);

    let search_key_str = match get_jstring(&mut env, &search_key_json) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    let search_key: SearchKey = match serde_json::from_str(&search_key_str) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to parse search_key: {}", e);
            return ptr::null_mut();
        }
    };

    let order_str = match get_jstring(&mut env, &order) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    let order: Order = match serde_json::from_str(&format!("\"{}\"", order_str)) {
        Ok(o) => o,
        Err(e) => {
            error!("Failed to parse order: {}", e);
            return ptr::null_mut();
        }
    };

    let after_cursor: Option<JsonBytes> =
        if env.is_same_object(&cursor, JString::default()).unwrap_or(true) {
            None
        } else {
            get_jstring(&mut env, &cursor).and_then(|s| {
                if s.is_empty() {
                    None
                } else {
                    serde_json::from_str(&format!("\"{}\"", s)).ok()
                }
            })
        };

    let service = match cell_service() {
        Some(s) => s,
        None => return ptr::null_mut(),
    };

    match service.get_transactions(search_key, order, Uint32::from(limit as u32), after_cursor) {
        Ok(result) => to_jstring(&mut env, &result),
        Err(e) => {
            error!("get_transactions failed: {}", e);
            ptr::null_mut()
        }
    }
}

/// Get cells capacity
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeGetCellsCapacity(
    mut env: JNIEnv,
    _class: JClass,
    search_key_json: JString,
) -> jstring {
    check_running!(env);

    let search_key_str = match get_jstring(&mut env, &search_key_json) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    let search_key: SearchKey = match serde_json::from_str(&search_key_str) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to parse search_key: {}", e);
            return ptr::null_mut();
        }
    };

    let service = match cell_service() {
        Some(s) => s,
        None => return ptr::null_mut(),
    };

    match service.get_cells_capacity(search_key) {
        Ok(result) => to_jstring(&mut env, &result),
        Err(e) => {
            error!("get_cells_capacity failed: {}", e);
            ptr::null_mut()
        }
    }
}

/// Send transaction
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeSendTransaction(
    mut env: JNIEnv,
    _class: JClass,
    tx_json: JString,
) -> jstring {
    check_running!(env);

    let tx_str = match get_jstring(&mut env, &tx_json) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    let tx: Transaction = match serde_json::from_str(&tx_str) {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to parse transaction: {}", e);
            return ptr::null_mut();
        }
    };

    let service = match chain_service() {
        Some(s) => s,
        None => return ptr::null_mut(),
    };

    match service.send_transaction(tx) {
        Ok(hash) => to_jstring(&mut env, &hash),
        Err(e) => {
            error!("send_transaction failed: {}", e);
            ptr::null_mut()
        }
    }
}

/// Get transaction
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeGetTransaction(
    mut env: JNIEnv,
    _class: JClass,
    hash: JString,
) -> jstring {
    check_running!(env);

    let hash_str = match get_jstring(&mut env, &hash) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    let h256 = match H256::from_str(&hash_str) {
        Ok(h) => h,
        Err(e) => {
            error!("Invalid hash: {}", e);
            return ptr::null_mut();
        }
    };

    let service = match chain_service() {
        Some(s) => s,
        None => return ptr::null_mut(),
    };

    to_jstring(&mut env, &service.get_transaction(&h256))
}

/// Fetch transaction
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeFetchTransaction(
    mut env: JNIEnv,
    _class: JClass,
    hash: JString,
) -> jstring {
    check_running!(env);

    let hash_str = match get_jstring(&mut env, &hash) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    let h256 = match H256::from_str(&hash_str) {
        Ok(h) => h,
        Err(e) => {
            error!("Invalid hash: {}", e);
            return ptr::null_mut();
        }
    };

    let service = match chain_service() {
        Some(s) => s,
        None => return ptr::null_mut(),
    };

    to_jstring(&mut env, &service.fetch_transaction(&h256))
}

/// Estimate cycles
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeEstimateCycles(
    mut env: JNIEnv,
    _class: JClass,
    tx_json: JString,
) -> jstring {
    check_running!(env);

    let tx_str = match get_jstring(&mut env, &tx_json) {
        Some(s) => s,
        None => return ptr::null_mut(),
    };
    let tx: Transaction = match serde_json::from_str(&tx_str) {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to parse transaction: {}", e);
            return ptr::null_mut();
        }
    };

    let service = match chain_service() {
        Some(s) => s,
        None => return ptr::null_mut(),
    };

    match service.estimate_cycles(tx) {
        Ok(cycles) => {
            let result = ckb_jsonrpc_types::EstimateCycles { cycles };
            to_jstring(&mut env, &result)
        }
        Err(e) => {
            error!("estimate_cycles failed: {}", e);
            ptr::null_mut()
        }
    }
}
