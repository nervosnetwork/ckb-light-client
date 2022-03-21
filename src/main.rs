mod config;
mod error;
mod protocols;
mod storage;
mod subcmds;
mod types;
mod utils;

use config::AppConfig;

fn main() -> anyhow::Result<()> {
    env_logger::init();

    log::info!("Starting ...");

    AppConfig::load()?.execute()?;

    log::info!("Done.");

    Ok(())
}
