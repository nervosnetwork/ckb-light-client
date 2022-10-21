use std::time::Duration;

pub const REFRESH_PEERS_TOKEN: u64 = 0;
pub const FETCH_HEADER_TX_TOKEN: u64 = 1;
// notify token to send GetBlocksProof and GetBlocks for previously timeout requests
pub const GET_IDLE_BLOCKS_TOKEN: u64 = 2;

pub const REFRESH_PEERS_DURATION: Duration = Duration::from_secs(8);
pub const FETCH_HEADER_TX_DURATION: Duration = Duration::from_secs(3);
pub const GET_IDLE_BLOCKS_DURATION: Duration = Duration::from_secs(3);
