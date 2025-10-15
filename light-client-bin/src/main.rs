mod cli;
mod rpc;
mod subcmds;

#[cfg(test)]
#[macro_use]
mod tests;

use cli::AppConfig;
use env_logger::{Builder, Env, Target};

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

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
