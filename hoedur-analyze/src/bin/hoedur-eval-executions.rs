use std::{io::Write, path::PathBuf};

use anyhow::Result;
use archive::{Archive, ArchiveEntry};
use clap::Parser;
use common::{
    fs::{bufwriter, decoder},
    log::{init_log, LOG_INFO},
};
use fuzzer::{FuzzerEntry, FuzzerEntryKind};
use hoedur_analyze::executions::ExecutionsPlot;

#[derive(Parser, Debug)]
#[command(name = "hoedur-eval-executions")]
pub struct Arguments {
    #[arg(long, default_value = LOG_INFO)]
    pub log_config: PathBuf,

    pub output: PathBuf,
    pub corpus_archive: PathBuf,
}

fn main() -> Result<()> {
    let opt = Arguments::parse();

    init_log(&opt.log_config)?;
    log::trace!("Args: {:#?}", opt);

    // load corpus archive
    log::info!(
        "Loading corpus archive {} ...",
        opt.corpus_archive.display()
    );
    let mut corpus_archive = Archive::from_reader(decoder(&opt.corpus_archive)?);

    for entry in corpus_archive.iter()? {
        // skip corrupt entries
        let mut entry: ArchiveEntry<_, FuzzerEntryKind> = match entry {
            Ok(entry) => entry,
            Err(err) => {
                log::error!("Failed to parse entry: {:?}", err);
                continue;
            }
        };

        // skip other entries
        if !matches!(entry.kind(), Some(FuzzerEntryKind::ExecutionsHistory)) {
            continue;
        }

        // parse statistics
        match entry.parse_entry() {
            Some(Ok(FuzzerEntry::ExecutionsHistory(executions))) => {
                let plot = ExecutionsPlot::from_history(executions);

                if let Some((time, value)) = plot.total.executions.last() {
                    writeln!(
                        bufwriter(&opt.output)?,
                        "# fuzz_duration total_executions execs/s\n{}\t{}\t{:.1}",
                        time.round(),
                        value.round(),
                        value / time
                    )?;
                    return Ok(());
                }
            }
            Some(Err(err)) => {
                log::error!("Failed to parse entry: {:?}", err);
            }
            _ => unreachable!(),
        }
    }

    Ok(())
}
