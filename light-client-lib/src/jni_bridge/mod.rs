//! JNI bridge for Android
//!
//! This module provides JNI bindings to expose CKB Light Client functionality
//! to Android applications.
//!
//! ## Architecture
//!
//! - `types`: Global state management using OnceLock pattern
//! - `lifecycle`: Init/start/stop/status lifecycle management
//! - `callbacks`: Log and status callbacks with batching
//! - `query`: 17 query APIs matching WASM implementation
//!
//! ## State Machine
//!
//! - 0 (INIT): Initialized but not started
//! - 1 (RUNNING): Running
//! - 2 (STOPPED): Stopped
//!
//! ## Thread Model
//!
//! - Main JNI calls run on Android threads
//! - Dedicated native thread runs tokio runtime
//! - Callbacks attach/detach from JVM as needed

pub mod callbacks;
pub mod lifecycle;
pub mod query;
pub mod rpc_handler;
pub mod types;

// Re-export main entry points
pub use lifecycle::{
    Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeGetStatus,
    Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeInit,
    Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeStart,
    Java_com_nervosnetwork_ckblightclient_LightClientNative_nativeStop,
};

pub use query::*;

pub use rpc_handler::Java_com_nervosnetwork_ckblightclient_LightClientNative_callRpc;
