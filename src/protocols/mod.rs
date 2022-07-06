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
// if GetBlockProof requests greater than 64, ban the peer
pub const MAX_BLOCK_RPOOF_REQUESTS: usize = 64;
// if have GetBlockProof request last more than 60 seconds, ban the peer
pub const GET_BLOCK_PROOF_TIMEOUT: u64 = 60 * 1000;

pub const LAST_N_BLOCKS: BlockNumber = 100;
