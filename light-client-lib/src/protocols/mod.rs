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

pub use light_client::{FetchInfo, LastState, PeerState, ProveRequest, ProveState};

pub use filter::FilterProtocol;
pub use light_client::{LightClientProtocol, Peers};
pub use relayer::{PendingTxs, RelayProtocol};
pub use status::{Status, StatusCode};
pub use synchronizer::SyncProtocol;

// The period to ban a peer for bad messages.
pub const BAD_MESSAGE_BAN_TIME: Duration = Duration::from_secs(5 * 60);
// Ban a peer if unexpected responses from that peer reach the limit.
pub const BAD_MESSAGE_ALLOWED_EACH_HOUR: u32 = 10;
// Ban a peer if it reach any timeout.
pub const MESSAGE_TIMEOUT: u64 = 60 * 1000;

pub const LAST_N_BLOCKS: BlockNumber = 100;

// Copy from ckb/util/light-client-protocol-server
pub const GET_BLOCKS_PROOF_LIMIT: usize = 1000;
// Copy from ckb/util/light-client-protocol-server
pub const GET_TRANSACTIONS_PROOF_LIMIT: usize = 1000;
// Copy from ckb/sync
pub const CHECK_POINT_INTERVAL: BlockNumber = 2000;
