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
