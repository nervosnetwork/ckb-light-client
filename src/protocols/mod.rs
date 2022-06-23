use std::time::Duration;

use ckb_types::core::BlockNumber;

mod filter;
mod light_client;
mod relayer;
mod status;
mod synchronizer;

pub(crate) use filter::FilterProtocol;
pub(crate) use light_client::{LightClientProtocol, Peers};
pub(crate) use relayer::{PendingTxs, RelayProtocol};
pub(crate) use status::{Status, StatusCode};
pub(crate) use synchronizer::SyncProtocol;

pub const BAD_MESSAGE_BAN_TIME: Duration = Duration::from_secs(5 * 60);

pub const LAST_N_BLOCKS: BlockNumber = 100;
