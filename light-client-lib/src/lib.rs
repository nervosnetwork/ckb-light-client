#![allow(clippy::mutable_key_type)]

#[cfg(test)]
#[macro_use]
mod tests;

pub mod error;
pub mod protocols;
pub mod service;
pub mod storage;
pub mod types;
pub mod utils;
pub mod verify;

// JNI bridge for Android
#[cfg(all(feature = "jni-bridge", target_os = "android"))]
pub mod jni_bridge;
