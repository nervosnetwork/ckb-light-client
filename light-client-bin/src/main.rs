mod cli;
mod rpc;
mod subcmds;

#[cfg(test)]
#[macro_use]
mod tests;

use cli::AppConfig;
use env_logger::{Builder, Env, Target};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() -> anyhow::Result<()> {
    let _profiler = dhat::Profiler::new_heap();
    
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
