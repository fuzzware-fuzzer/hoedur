use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use common::{
    fs::encoder,
    log::{init_log, LOG_INFO},
};
use hoedur::coverage::CoverageReport;

#[derive(Parser, Debug)]
#[command(name = "hoedur-merge-report")]
pub struct Arguments {
    #[arg(long, default_value = LOG_INFO)]
    pub log_config: PathBuf,

    #[arg(long)]
    pub name: String,

    #[arg(long)]
    pub output: PathBuf,
    pub report: Vec<PathBuf>,
}

fn main() -> Result<()> {
    let opt = Arguments::parse();

    init_log(&opt.log_config)?;
    log::trace!("Args: {:#?}", opt);

    let mut report_group = CoverageReport::new(opt.name);

    // load and merge reports
    for path in opt.report {
        log::info!("Loading coverage report {:?} ...", path);
        let report = CoverageReport::load_from(&path)?;

        unsafe {
            report_group.merge(report);
        }
    }

    // write merged report
    bincode::serialize_into(
        encoder(&opt.output).context("Failed to open output file")?,
        &report_group,
    )
    .context("Failed to serialize report")
}
