use std::{fmt, path::PathBuf, result::Result as StdResult, str::FromStr};

use ckb_app_config::NetworkConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RunEnv {
    pub chain: String,
    pub store: StoreConfig,
    pub network: NetworkConfig,
    pub rpc: RpcConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct StoreConfig {
    pub path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RpcConfig {
    pub listen_address: String,
}

impl FromStr for RunEnv {
    type Err = toml::de::Error;
    fn from_str(s: &str) -> StdResult<Self, Self::Err> {
        toml::from_str(s)
    }
}

impl fmt::Display for RunEnv {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        toml::to_string_pretty(self)
            .map_err(|_| fmt::Error)
            .and_then(|s| write!(f, "{}", s))
    }
}

/**
 * RwLock type used on wasm. On wasm, std::sync::RwLock doesn't work properly on single-thread async environment.
 */
#[cfg(target_arch = "wasm32")]
pub type RwLock<T> = tokio::sync::RwLock<T>;
#[cfg(target_arch = "wasm32")]
pub type Mutex<T> = tokio::sync::Mutex<T>;

#[cfg(not(target_arch = "wasm32"))]
pub type RwLock<T> = std::sync::RwLock<T>;
#[cfg(not(target_arch = "wasm32"))]
pub type Mutex<T> = std::sync::Mutex<T>;

#[cfg(not(target_arch = "wasm32"))]
pub use std::time::{Duration, Instant};
/**
 * Unified time types for cross-platform compatibility
 */
#[cfg(target_arch = "wasm32")]
pub use web_time::{Duration, Instant};

/**
 * Macros for unified lock access patterns.
 * These eliminate duplicate cfg blocks while maintaining zero-cost abstraction.
 */
#[macro_export]
macro_rules! read_lock {
    ($lock:expr) => {{
        #[cfg(target_arch = "wasm32")]
        {
            $lock.read().await
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            $lock.read().unwrap()
        }
    }};
}

#[macro_export]
macro_rules! write_lock {
    ($lock:expr) => {{
        #[cfg(target_arch = "wasm32")]
        {
            $lock.write().await
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            $lock.write().unwrap()
        }
    }};
}

#[macro_export]
macro_rules! mutex_lock {
    ($lock:expr) => {{
        #[cfg(target_arch = "wasm32")]
        {
            $lock.lock().await
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            $lock.lock().unwrap()
        }
    }};
}
