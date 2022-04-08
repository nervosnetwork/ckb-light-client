use std::time::Duration;

mod block_filter;
mod components;

const BAD_MESSAGE_BAN_TIME: Duration = Duration::from_secs(5 * 60);

pub use block_filter::FilterProtocol;
