use std::time::Duration;

pub const BAD_MESSAGE_BAN_TIME: Duration = Duration::from_secs(5 * 60);

pub const WAIT_FOR_PEERS_TOKEN: u64 = 0;
pub const GET_CHAIN_INFO_TOKEN: u64 = 1;
pub const GET_LAST_HEADER_TOKEN: u64 = 1;
pub const FIND_HONEST_PEER_TOKEN: u64 = 3;

pub const WAIT_FOR_PEERS_DURATION: Duration = Duration::from_secs(30);
pub const GET_CHAIN_INFO_DURATION: Duration = Duration::from_secs(30);
pub const GET_LAST_HEADER_DURATION: Duration = Duration::from_secs(30);
pub const FIND_HONEST_PEER_DURATION: Duration = Duration::from_secs(5);
