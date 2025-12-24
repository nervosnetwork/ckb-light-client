//! RPC handler for JNI bridge
//!
//! Provides direct JNI methods for RPC calls instead of HTTP server

use super::types::*;
use crate::service::ScriptStatus;
use ckb_jsonrpc_types::{BlockView, HeaderView};
use ckb_network::extract_peer_id;
use ckb_types::prelude::{IntoBlockView, IntoHeaderView};
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
    // Get method name
    let method: String = match env.get_string(&method_jstr) {
        Ok(s) => s.into(),
        Err(e) => {
            error!("Failed to get method name: {}", e);
            return jni_rpc_error!(&mut env, -32700, "Failed to parse method name");
        }
    };

    // Get storage
    let swc = match STORAGE_WITH_DATA.get() {
        Some(s) => s,
        None => {
            warn!("Storage not initialized for method: {}", method);
            return jni_rpc_error!(&mut env, -32603, "Light client not initialized");
        }
    };

    // Handle different RPC methods
    match method.as_str() {
        "get_peers" => {
            // Get network controller
            let net_ctrl = match NET_CONTROL.get() {
                Some(nc) => nc,
                None => {
                    return jni_rpc_error!(&mut env, -32603, "Network controller not initialized");
                }
            };

            // Get connected peers
            let peers = net_ctrl
                .connected_peers()
                .iter()
                .map(|(peer_index, peer)| {
                    let mut addresses = vec![&peer.connected_addr];
                    addresses.extend(peer.listened_addrs.iter());

                    let node_addresses: Vec<_> = addresses
                        .iter()
                        .map(|addr| {
                            let score = net_ctrl
                                .addr_info(addr)
                                .map(|addr_info| addr_info.score)
                                .unwrap_or(1);
                            let non_negative_score = if score > 0 { score as u64 } else { 0 };
                            json!({
                                "address": addr.to_string(),
                                "score": format!("0x{:x}", non_negative_score)
                            })
                        })
                        .collect();

                    // Get sync state from PEERS
                    let sync_state = PEERS.get().and_then(|peers_mgr| {
                        peers_mgr.get_state(peer_index).map(|state| {
                            json!({
                                "requested_best_known_header": state.get_prove_request().map(|req| {
                                    let header: HeaderView = req.get_last_header().header().to_owned().into();
                                    header
                                }),
                                "proved_best_known_header": state.get_prove_state().map(|req| {
                                    let header: HeaderView = req.get_last_header().header().to_owned().into();
                                    header
                                })
                            })
                        })
                    });

                    json!({
                        "version": peer.identify_info.as_ref()
                            .map(|info| info.client_version.clone())
                            .unwrap_or_else(|| "unknown".to_string()),
                        "node_id": extract_peer_id(&peer.connected_addr)
                            .map(|peer_id| peer_id.to_base58())
                            .unwrap_or_default(),
                        "addresses": node_addresses,
                        "connected_duration": format!("0x{:x}",
                            std::time::Instant::now()
                                .saturating_duration_since(peer.connected_time)
                                .as_millis() as u64
                        ),
                        "sync_state": sync_state,
                        "protocols": peer.protocols.iter().map(|(protocol_id, protocol_version)| {
                            json!({
                                "id": format!("0x{:x}", protocol_id.value() as u64),
                                "version": protocol_version
                            })
                        }).collect::<Vec<_>>()
                    })
                })
                .collect::<Vec<_>>();

            jni_rpc_response!(&mut env, peers)
        }

        "get_tip_header" => {
            let tip_header = swc.storage().get_tip_header();
            let header_view: HeaderView = tip_header.into_view().into();
            jni_rpc_response!(&mut env, header_view)
        }

        "get_genesis_block" => {
            let genesis_block = swc.storage().get_genesis_block();
            let block_view: BlockView = genesis_block.into_view().into();
            jni_rpc_response!(&mut env, block_view)
        }

        "get_scripts" => {
            let scripts = swc.storage().get_filter_scripts();
            let script_statuses: Vec<ScriptStatus> =
                scripts.into_iter().map(|s| s.into()).collect();
            jni_rpc_response!(&mut env, script_statuses)
        }

        _ => {
            let error_msg = format!("Unknown method: {}", method);
            warn!("{}", error_msg);
            jni_rpc_error!(&mut env, -32601, error_msg)
        }
    }
}
