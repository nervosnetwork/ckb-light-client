#![allow(clippy::mutable_key_type)]

#[cfg(test)]
#[macro_use]
mod tests;

mod config;
mod error;
mod protocols;
mod service;
mod storage;
mod subcmds;
mod types;
mod utils;
mod verify;

// TODO Remove the patches if the code was merged into CKB.
mod patches;

use config::AppConfig;

fn main() -> anyhow::Result<()> {
    env_logger::init();

    log::info!("Starting ...");

    AppConfig::load()?.execute()?;

    log::info!("Done.");

    Ok(())
}
