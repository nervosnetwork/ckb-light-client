#[macro_use]
mod prelude;

pub(crate) mod utils;

// The unit tests for modules which are in the root path of this crate.
mod protocols;
mod service;
mod verify;

pub const ALWAYS_SUCCESS_BIN: &[u8] = include_bytes!("specs/cells/always_success");
