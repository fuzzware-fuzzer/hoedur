use std::{fmt::Write, path::PathBuf};

use anyhow::{Context, Result};
use archive::tar::{write_file, write_tar};
use clap::Parser;
use common::{
    fs::{bufwriter, encoder},
    log::{init_log, LOG_INFO},
    time::epoch,
    FxHashSet,
};
use hoedur::coverage::CoverageReport;
use hoedur_analyze::coverage::Filter;

#[derive(Parser, Debug)]
#[command(name = "hoedur-coverage-list")]
pub struct Arguments {
    #[arg(long, default_value = LOG_INFO)]
    pub log_config: PathBuf,

    #[arg(long)]
    pub output: PathBuf,
    #[arg(long)]
    pub output_superset: Option<PathBuf>,

    pub report: PathBuf,

    /// Valid basic blocks (include list)
    #[arg(long)]
    pub valid_basic_blocks: Option<PathBuf>,
    /// Disable valid input filter
    #[arg(long)]
    pub no_filter: bool,
    /// Filter inputs by bug
    #[arg(long, conflicts_with = "no_filter", num_args(1))]
    pub filter_bug: Vec<String>,
}

fn main() -> Result<()> {
    let opt = Arguments::parse();

    init_log(&opt.log_config)?;
    log::trace!("Args: {:#?}", opt);

    let bb_filter = opt
        .valid_basic_blocks
        .as_deref()
        .map(Filter::with_include)
        .transpose()?
        .unwrap_or_else(Filter::none);

    let filter_bugs = (!opt.filter_bug.is_empty()).then(|| {
        opt.filter_bug
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    });

    log::info!("Loading coverage report {:?} ...", opt.report);
    let report = CoverageReport::load_from(&opt.report)?;

    let path = &opt.output;
    let writer = encoder(path).with_context(|| format!("Failed to create output file {path:?}"))?;

    let output_superset = &opt.output_superset;
    let mut superset = FxHashSet::default();
    write_tar(writer, epoch()?, |archive| {
        for input in report
            .inputs()
            .iter()
            .filter(|coverage| opt.no_filter || coverage.is_valid(filter_bugs.as_deref()))
        {
            // apply basic block filter
            let mut coverage: Vec<_> = input
                .coverage()
                .iter()
                .filter(|pc| {
                    bb_filter
                        .include
                        .as_ref()
                        .map(|include| include.contains(*pc))
                        .unwrap_or(true)
                })
                .collect();

            // sort coverage
            coverage.sort_unstable();

            // write coverage file
            let mut buffer = String::new();
            for pc in &coverage {
                superset.insert(**pc);
                writeln!(&mut buffer, "{pc:#x?}").context("Failed to write pc line")?;
            }

            // add to archive
            write_file(
                archive,
                &format!("coverage/input-{}.txt", *input.id()),
                epoch()?,
                buffer.as_bytes(),
            )
            .context("Failed to add coverage file to archive")?;
        }

        let mut list: Vec<_> = superset.into_iter().collect();
        list.sort_unstable();

        // write superset
        let mut buffer = String::new();
        for pc in list {
            writeln!(buffer, "{pc:#x?}").context("Failed to write pc line")?;
        }

        // add to archive
        write_file(
            archive,
            "coverage-superset.txt",
            epoch()?,
            buffer.as_bytes(),
        )
        .context("Failed to add coverage file to archive")?;

        // optionally write superset file
        if let Some(path) = output_superset {
            use std::io::Write;
            bufwriter(path)
                .context("Failed to create output file")?
                .write_all(buffer.as_bytes())
                .context("Failed to write superset file")?;
        }

        Ok(())
    })
    .context("Failed to write output tar file")?;

    Ok(())
}
