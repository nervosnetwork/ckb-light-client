use std::time::Duration;

use ckb_types::core::BlockNumber;

#[macro_use]
mod status;

mod filter;
pub(crate) mod light_client;
mod relayer;
mod synchronizer;

#[cfg(test)]
pub(crate) use filter::GET_BLOCK_FILTERS_TOKEN;
#[cfg(test)]
pub(crate) use light_client::{LastState, PeerState, ProveRequest, ProveState};

pub(crate) use filter::FilterProtocol;
pub(crate) use light_client::{LightClientProtocol, Peers};
pub(crate) use relayer::{PendingTxs, RelayProtocol};
pub(crate) use status::{Status, StatusCode};
pub(crate) use synchronizer::SyncProtocol;

pub const BAD_MESSAGE_BAN_TIME: Duration = Duration::from_secs(5 * 60);
// Ban a peer if it reach any timeout.
pub const MESSAGE_TIMEOUT: u64 = 60 * 1000;

pub const LAST_N_BLOCKS: BlockNumber = 100;
