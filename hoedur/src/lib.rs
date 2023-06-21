mod archive;
pub mod cli;
pub mod coverage;
mod hoedur;
mod runner;

use anyhow::Context;
use modeling::input::InputFile;

pub use crate::archive::create_archive;
pub use crate::hoedur::HoedurConfig;
pub use runner::{run, Command, RunConfig, RunnerConfig};

pub type Emulator = emulator::Emulator<InputFile>;

pub fn main() -> anyhow::Result<()> {
    use clap::Parser;
    let opt = cli::Arguments::parse();

    // init log config
    common::log::init_log(&opt.log_config)?;
    log::trace!("Args: {:#?}", opt);

    // create config from cli args
    let config =
        RunnerConfig::from_cli(opt).context("Failed to create emulator config from arguments")?;
    log::trace!("config = {:#?}", config);

    // run fuzzer / single input
    run(config)
        .context("Failed to run fuzzer / input")
        .map_err(|e| {
            log::error!("{:?}", e);
            e
        })
}
