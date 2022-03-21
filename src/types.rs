use std::{fmt, path::PathBuf, result::Result as StdResult, str::FromStr};

use ckb_app_config::NetworkConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunEnv {
    pub(crate) chain: String,
    pub(crate) store: StoreConfig,
    pub(crate) network: NetworkConfig,
    pub(crate) light_client: LightClientConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoreConfig {
    pub(crate) path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct LightClientConfig {
    pub(crate) strategy: BlockSamplingStrategy,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) enum BlockSamplingStrategy {
    NaiveApproach,
    BinarySearchApproach,
    BoundingTheForkPoint,
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
