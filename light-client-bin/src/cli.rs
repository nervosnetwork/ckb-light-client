use std::{convert::TryFrom, fmt::Display, fs::OpenOptions, io::Read as _, str::FromStr};

use ckb_light_client_lib::{
    error::{Error, Result},
    types::RunEnv,
};

pub(crate) enum AppConfig {
    Run(RunConfig),
}

pub(crate) struct RunConfig {
    pub(crate) run_env: RunEnv,
}

impl AppConfig {
    pub(crate) fn load() -> Result<Self> {
        let cmd = clap::Command::new("CKB Light Client")
            .version(clap::crate_version!())
            .author(clap::crate_authors!("\n"))
            .about(clap::crate_description!())
            .subcommand_required(true)
            .subcommand(
                clap::Command::new("run")
                    .about("Run the CKB light client.")
                    .arg(
                        clap::Arg::new("config-file")
                            .long("config-file")
                            .required(true)
                            .action(clap::ArgAction::Set)
                            .help("The config file which includes the running parameters."),
                    ),
            )
            .get_matches();

        Self::try_from(cmd)
    }

    pub(crate) fn execute(self) -> Result<()> {
        log::info!("Executing ...");
        match self {
            Self::Run(cfg) => cfg.execute(),
        }
    }
}

impl TryFrom<clap::ArgMatches> for AppConfig {
    type Error = Error;
    fn try_from(matches: clap::ArgMatches) -> Result<Self> {
        match matches.subcommand().unwrap() {
            ("run", submatches) => RunConfig::try_from(submatches).map(AppConfig::Run),
            (subcmd, _) => Err(Error::config(format!("subcommand {}", subcmd))),
        }
    }
}

impl TryFrom<&clap::ArgMatches> for RunConfig {
    type Error = Error;
    fn try_from(matches: &clap::ArgMatches) -> Result<Self> {
        let run_env = parse_from_file::<RunEnv>(matches, "config-file")?;
        Ok(Self { run_env })
    }
}

fn parse_from_file<T: FromStr>(matches: &clap::ArgMatches, name: &str) -> Result<T>
where
    <T as FromStr>::Err: Display,
{
    matches
        .get_one::<String>(name)
        .map(|file| {
            OpenOptions::new()
                .read(true)
                .open(file)
                .map_err(|err| Error::config(format!("failed to open {} since {}", file, err)))
                .and_then(|mut f| {
                    let mut buffer = String::new();
                    f.read_to_string(&mut buffer)
                        .map_err(|err| {
                            Error::config(format!("failed to read {} since {}", file, err))
                        })
                        .map(|_| buffer)
                })
                .and_then(|data| T::from_str(&data).map_err(Error::config))
        })
        .transpose()?
        .ok_or_else(|| Error::argument_should_exist(name))
}
