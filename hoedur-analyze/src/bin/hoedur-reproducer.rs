use std::path::PathBuf;

use anyhow::{Context, Result};
use archive::Archive;
use clap::Parser;
use common::{
    fs::{bufwriter, decoder},
    hashbrown::hash_map::Entry,
    log::{init_log, LOG_INFO},
    FxHashMap,
};
use fuzzer::{CorpusEntry, CorpusEntryKind};
use hoedur::coverage::CoverageReport;
use modeling::hardware::WriteTo;

#[derive(Parser, Debug)]
#[command(name = "hoedur-reproducer")]
pub struct Arguments {
    #[arg(long, default_value = LOG_INFO)]
    pub log_config: PathBuf,

    /// Output dir for config archive + reproducer inputs
    pub output: PathBuf,

    /// Corpus archive file
    #[arg(long)]
    pub corpus_archive: PathBuf,

    /// Coverage report file
    #[arg(long)]
    pub report: PathBuf,
}

fn main() -> Result<()> {
    let opt = Arguments::parse();

    init_log(&opt.log_config)?;
    log::trace!("Args: {:#?}", opt);

    log::info!("Loading coverage report {:?} ...", opt.report);
    let report = CoverageReport::load_from(&opt.report)
        .with_context(|| format!("Failed to load coverage report {:?}", opt.report))?;

    // collect input->crash reason mapping
    let mut inputs = FxHashMap::default();
    for input in report.inputs() {
        if let Some(crash_reason) = input.crash_reason() {
            inputs.insert(input.id(), crash_reason);
        }
    }

    log::info!(
        "Loading corpus archive {} ...",
        opt.corpus_archive.display()
    );
    let mut corpus_archive = Archive::from_reader(
        decoder(&opt.corpus_archive).context("Failed to load corpus archive")?,
    );

    // create config archive
    let mut config_archive = archive::create_archive(&opt.output, "config", true, true)
        .context("Failed to create config archive")?;

    // copy config files + collect inputs
    let mut reproducers = FxHashMap::default();
    for entry in corpus_archive.iter::<CorpusEntryKind>()? {
        let mut entry = entry?;

        match entry.kind() {
            Some(CorpusEntryKind::Common(_))
            | Some(CorpusEntryKind::Emulator(_))
            | Some(CorpusEntryKind::Modeling(_)) => {
                let header = entry.header().clone();
                config_archive
                    .append(&header, entry.raw_entry())
                    .with_context(|| {
                        format!(
                            "Failed to append {:?} to config archive",
                            header.path().unwrap_or_default(),
                        )
                    })?;
            }
            Some(CorpusEntryKind::InputFile(_)) => {
                if let CorpusEntry::InputFile { input, .. } =
                    entry.parse_entry().unwrap().with_context(|| {
                        format!("Failed to parse input file {:?}", entry.header().path())
                    })?
                {
                    // collect shortest input per crash reason
                    if let Some(crash_reason) = inputs.get(&input.id()) {
                        match reproducers.entry(crash_reason) {
                            Entry::Vacant(entry) => {
                                entry.insert(input);
                            }
                            Entry::Occupied(mut entry) => {
                                let reproducer = entry.get_mut();

                                if input.len() < reproducer.len() {
                                    *reproducer = input;
                                }
                            }
                        }
                    }
                } else {
                    unreachable!()
                }
            }
            Some(CorpusEntryKind::Fuzzer(_)) => {
                // remove fuzzer statistics
                log::debug!("skipping corpus entry {:#?}", entry.header().path());
            }
            None => {
                log::warn!(
                    "unknown corpus entry at {:?}",
                    entry.header().path().unwrap_or_default()
                );
            }
        }
    }

    // write reproducer input files
    for (crash_reason, input) in reproducers {
        let path = opt.output.join(format!(
            "input-{}-reproducer-{}.bin",
            *input.id(),
            crash_reason.to_string()
        ));

        input
            .write_to(bufwriter(&path)?)
            .with_context(|| format!("Failed to write reproducer input file {:?}", path))?;
    }

    Ok(())
}
