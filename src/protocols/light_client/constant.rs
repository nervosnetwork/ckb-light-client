use std::time::Duration;

pub const REFRESH_PEERS_TOKEN: u64 = 0;
pub const FETCH_HEADER_TX_TOKEN: u64 = 1;

pub const REFRESH_PEERS_DURATION: Duration = Duration::from_secs(60);
pub const FETCH_HEADER_TX_DURATION: Duration = Duration::from_secs(3);

// Copy from ckb/util/light-client-protocol-server
pub const GET_BLOCKS_PROOF_LIMIT: usize = 1000;
// Copy from ckb/util/light-client-protocol-server
pub const GET_TRANSACTIONS_PROOF_LIMIT: usize = 1000;
