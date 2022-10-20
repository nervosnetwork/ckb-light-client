#[macro_use]
mod prelude;

pub(crate) mod utils;

// The unit tests for modules which are in the root path of this crate.
mod protocols;
mod service;
mod storage;
mod verify;

use ckb_types::{
    core::ScriptHashType,
    packed::{CellOutput, Script},
    prelude::*,
};

pub const ALWAYS_SUCCESS_BIN: &[u8] = include_bytes!("specs/cells/always_success");

lazy_static::lazy_static! {
    pub static ref ALWAYS_SUCCESS_SCRIPT: Script = Script::new_builder()
            .hash_type(ScriptHashType::Data.into())
            .code_hash(CellOutput::calc_data_hash(ALWAYS_SUCCESS_BIN))
            .build();
}
