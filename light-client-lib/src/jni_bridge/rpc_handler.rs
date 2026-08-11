//! RPC handler for JNI bridge
//!
//! Provides direct JNI methods for RPC calls, delegating to the unified service layer.

use super::types::*;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;
use log::{error, warn};
use serde_json::json;
use std::ptr;

/// Helper macro to create JSON-RPC response string
macro_rules! jni_rpc_response {
    ($env:expr, $result:expr) => {{
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": $result
        });
        match serde_json::to_string(&response) {
            Ok(json_str) => match $env.new_string(json_str) {
                Ok(s) => s.into_raw(),
                Err(e) => {
                    error!("Failed to create JString: {}", e);
                    ptr::null_mut()
                }
            },
            Err(e) => {
                error!("Failed to serialize response: {}", e);
                ptr::null_mut()
            }
        }
    }};
}

/// Helper macro to create JSON-RPC error response
macro_rules! jni_rpc_error {
    ($env:expr, $code:expr, $message:expr) => {{
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": $code,
                "message": $message
            }
        });
        match serde_json::to_string(&response) {
            Ok(json_str) => match $env.new_string(json_str) {
                Ok(s) => s.into_raw(),
                Err(e) => {
                    error!("Failed to create error JString: {}", e);
                    ptr::null_mut()
                }
            },
            Err(e) => {
                error!("Failed to serialize error response: {}", e);
                ptr::null_mut()
            }
        }
    }};
}

const MAX_ADDRS: usize = 50;

/// JNI: Call RPC method
///
/// This provides a generic RPC interface that handles common methods:
/// - get_peers
/// - get_tip_header
/// - get_genesis_block
/// - get_scripts
///
/// Returns JSON-RPC 2.0 formatted response as string
#[no_mangle]
pub extern "C" fn Java_com_nervosnetwork_ckblightclient_LightClientNative_callRpc(
    mut env: JNIEnv,
    _class: JClass,
    method_jstr: JString,
) -> jstring {
    let method: String = match env.get_string(&method_jstr) {
        Ok(s) => s.into(),
        Err(e) => {
            error!("Failed to get method name: {}", e);
            return jni_rpc_error!(&mut env, -32700, "Failed to parse method name");
        }
    };

    match method.as_str() {
        "get_peers" => {
            let service = match network_service() {
                Some(s) => s,
                None => {
                    return jni_rpc_error!(&mut env, -32603, "Network service not initialized");
                }
            };
            let peers = service.get_peers();
            jni_rpc_response!(&mut env, peers)
        }

        "get_tip_header" => {
            let service = match chain_service() {
                Some(s) => s,
                None => {
                    return jni_rpc_error!(&mut env, -32603, "Light client not initialized");
                }
            };
            jni_rpc_response!(&mut env, service.get_tip_header())
        }

        "get_genesis_block" => {
            let service = match chain_service() {
                Some(s) => s,
                None => {
                    return jni_rpc_error!(&mut env, -32603, "Light client not initialized");
                }
            };
            jni_rpc_response!(&mut env, service.get_genesis_block())
        }

        "get_scripts" => {
            let service = match chain_service() {
                Some(s) => s,
                None => {
                    return jni_rpc_error!(&mut env, -32603, "Light client not initialized");
                }
            };
            jni_rpc_response!(&mut env, service.get_scripts())
        }

        "local_node_info" => {
            let service = match network_service() {
                Some(s) => s,
                None => {
                    return jni_rpc_error!(&mut env, -32603, "Network service not initialized");
                }
            };
            jni_rpc_response!(&mut env, service.local_node_info(MAX_ADDRS))
        }

        _ => {
            let error_msg = format!("Unknown method: {}", method);
            warn!("{}", error_msg);
            jni_rpc_error!(&mut env, -32601, error_msg)
        }
    }
}
