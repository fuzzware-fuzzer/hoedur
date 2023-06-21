use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use archive::{Archive, ArchiveEntry};
use clap::Parser;
use common::{
    fs::{decoder, encoder},
    log::{init_log, LOG_INFO},
};
use fuzzer::{
    statistics::{ExecutionsHistory, InputSizeHistory},
    FuzzerEntry, FuzzerEntryKind,
};
use hoedur::coverage::CoverageReport;
use hoedur_analyze::{
    coverage::{CoverageReportExt, Filter},
    executions::ExecutionsPlot,
    input::InputPlot,
    plot::PlotWriter,
};
use std::io::Write;

#[derive(Parser, Debug)]
#[command(name = "hoedur-plot-data")]
pub struct Arguments {
    #[arg(long, default_value = LOG_INFO)]
    pub log_config: PathBuf,

    pub output: PathBuf,

    /// Corpus archive file
    #[arg(long)]
    pub corpus_archive: Option<PathBuf>,

    /// Coverage report file
    #[arg(long)]
    pub report: Option<PathBuf>,

    /// Valid basic blocks (include list)
    #[arg(long, requires = "report")]
    pub valid_basic_blocks: Option<PathBuf>,

    /// Filter inputs by bug (exclude list)
    #[arg(long = "filter-bug", num_args(1), requires = "report")]
    pub bugs_filter: Vec<String>,
}

fn main() -> Result<()> {
    let opt = Arguments::parse();

    init_log(&opt.log_config)?;
    log::trace!("Args: {:#?}", opt);

    let mut output = encoder(&opt.output)?;
    let mut writer = PlotWriter::new(&mut output)?;

    // statistics in corpus archive
    if let Some(corpus_archive) = opt.corpus_archive {
        hoedur_plots(&mut writer, &corpus_archive)?;
    }

    // basic block coverage
    if let Some(report) = opt.report {
        coverage_plot(&mut writer, report, opt.valid_basic_blocks, opt.bugs_filter)?;
    }

    // finish JSON file
    writer.finish()?;

    // flush output
    output.flush().context("Failed to flash JSON output")
}

fn coverage_plot<W: Write>(
    writer: &mut PlotWriter<W>,
    report: PathBuf,
    valid_basic_blocks: Option<PathBuf>,
    bugs_filter: Vec<String>,
) -> Result<()> {
    let bb_filter = valid_basic_blocks
        .as_deref()
        .map(Filter::with_include)
        .transpose()?
        .unwrap_or_else(Filter::none);

    let bugs_filter = (!bugs_filter.is_empty())
        .then(|| bugs_filter.iter().map(String::as_str).collect::<Vec<_>>());

    log::info!("Loading coverage report {:?} ...", report);
    match CoverageReport::load_from(&report) {
        Ok(report) => {
            writer.plot(
                "coverage_translation_blocks",
                &report.to_plot(&bb_filter, bugs_filter.as_deref()),
            )?;
        }
        Err(err) => {
            log::error!("Failed to load coverage report {:?}: {:?}", report, err);
        }
    }

    Ok(())
}

fn hoedur_plots<W: Write>(writer: &mut PlotWriter<W>, corpus_archive: &Path) -> Result<()> {
    log::info!("Loading corpus archive {} ...", corpus_archive.display());
    let mut corpus_archive = Archive::from_reader(decoder(corpus_archive)?);

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
        if !matches!(
            entry.kind(),
            Some(FuzzerEntryKind::ExecutionsHistory | FuzzerEntryKind::InputSizeHistory),
        ) {
            continue;
        }

        // parse statistics
        match entry.parse_entry() {
            Some(Ok(FuzzerEntry::ExecutionsHistory(executions))) => {
                executions_plot(writer, executions)?
            }
            Some(Ok(FuzzerEntry::InputSizeHistory(input_sizes))) => {
                input_plot(writer, &input_sizes)?
            }
            Some(Err(err)) => {
                log::error!("Failed to parse entry: {:?}", err);
            }
            _ => unreachable!(),
        }
    }

    Ok(())
}

fn executions_plot<W: Write>(
    writer: &mut PlotWriter<W>,
    executions: Vec<ExecutionsHistory>,
) -> Result<()> {
    let exec_plots = ExecutionsPlot::from_history(executions);
    log::debug!("exec_plots = {:?}", exec_plots);

    for (postfix, plots) in [
        ("total", exec_plots.total),
        ("per_second", exec_plots.per_second),
    ] {
        for (name, data) in [
            ("executions", plots.executions),
            ("minimizations", plots.minimizations),
            ("basic_blocks", plots.basic_blocks),
            ("interrupts", plots.interrupts),
            ("mmio_reads", plots.mmio_reads),
            ("mmio_writes", plots.mmio_writes),
        ] {
            writer.plot(&format!("{}_{}", name, postfix), &data)?;
        }
    }

    Ok(())
}

fn input_plot<W: Write>(
    writer: &mut PlotWriter<W>,
    input_sizes: &[InputSizeHistory],
) -> Result<()> {
    let input_plots = InputPlot::from_history(input_sizes);
    log::debug!("input_plots = {:?}", input_plots);

    for (name, data) in [
        ("input_count", input_plots.count),
        ("input_mean_size", input_plots.size_values.mean_size),
        ("input_mean_size_bytes", input_plots.size_bytes.mean_size),
        ("input_median_size", input_plots.size_values.median_size),
        (
            "input_median_size_bytes",
            input_plots.size_bytes.median_size,
        ),
        ("input_max_size", input_plots.size_values.max_size),
        ("input_max_size_bytes", input_plots.size_bytes.max_size),
    ] {
        writer.plot(name, &data)?;
    }

    Ok(())
}
