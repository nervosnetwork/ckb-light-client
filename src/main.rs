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
use env_logger::{Builder, Env, Target};

fn main() -> anyhow::Result<()> {
    let mut builder = Builder::from_env(Env::default());
    builder.target(Target::Stdout);
    builder
        .try_init()
        .expect("env_logger builder init should be ok");

    log::info!("Starting ...");

    AppConfig::load()?.execute()?;

    log::info!("Done.");

    Ok(())
}
