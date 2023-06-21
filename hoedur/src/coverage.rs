use std::{
    fmt::{self, Debug},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use archive::{common::CommonEntryKind, Archive, ArchiveBuilder};
use common::{
    exit::signal_exit_point,
    fs::{decoder, encoder},
    time::Epoch,
    FxHashSet,
};
use emulator::{Bug, EmulatorSnapshot, RunMode, StopReason};
use fuzzer::{write_input_file, CorpusInputFile, InputResult, IntoInputFileIter};
use modeling::input::InputId;
use qemu_rs::Address;
use serde::{Deserialize, Serialize};

use crate::{
    archive::{create_archive, opt_archive},
    cli,
    runner::verify_remaining_values,
    Emulator,
};

#[derive(Debug)]
pub struct RunCovConfig {
    pub(crate) archive: Option<ArchiveBuilder>,
    name: String,
    coverage_report: PathBuf,
    pub(crate) prefix_input: Vec<PathBuf>,
    corpus_paths: Vec<PathBuf>,
}

impl RunCovConfig {
    pub fn new(
        archive: Option<ArchiveBuilder>,
        name: String,
        coverage_report: PathBuf,
        prefix_input: Vec<PathBuf>,
        corpus_paths: Vec<PathBuf>,
    ) -> Self {
        Self {
            archive,
            name,
            coverage_report,
            prefix_input,
            corpus_paths,
        }
    }

    pub fn from_cli(name: &str, args: cli::RunCovArguments) -> Result<Self> {
        Ok(Self::new(
            opt_archive(&args.archive)
                .map(|archive_dir| create_archive(name, archive_dir))
                .transpose()?,
            name.into(),
            args.coverage_report,
            args.prefix.prefix_input,
            args.corpus_paths,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LegacyCoverageReport {
    name: String,
    source: Option<String>,
    commit: Option<String>,
    inputs: Vec<InputCoverage>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CoverageReport {
    name: String,
    commit: Option<String>,
    inputs: Vec<InputCoverage>,
}

impl fmt::Display for CoverageReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Coverage Report ({})", self.name())?;
        if let Some(commit) = self.commit() {
            write!(f, " (Commit: {commit})")?;
        }
        write!(f, ":")?;

        for input in self.inputs() {
            write!(f, "\n{input}")?;
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InputCoverage {
    id: InputId,
    timestamp: Option<Epoch>,
    stop_reason: StopReason,
    bugs: Option<Vec<Bug>>,
    coverage: FxHashSet<Address>,
}

impl fmt::Display for InputCoverage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Input {}", self.id())?;
        if let Some(timestamp) = self.timestamp() {
            write!(f, " ({timestamp} s)")?;
        }
        write!(
            f,
            ": {} tb coverage, {:x?}",
            self.coverage().len(),
            self.stop_reason()
        )?;

        if let Some(bugs) = self.bugs() {
            for bug in bugs {
                write!(f, ", bug {bug}")?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Serialize)]
pub enum CrashReason {
    BugCombination(Vec<String>),
    Crash { pc: Address, ra: Address },
    NonExecutable { pc: Address },
    RomWrite { pc: Address, addr: Address },
}

impl fmt::Display for CrashReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CrashReason::BugCombination(bugs) => write!(f, "{}", bugs.join("+")),
            CrashReason::Crash { pc, ra } => write!(f, "crash_ra-{ra:08x}_pc-{pc:08x}"),
            CrashReason::NonExecutable { pc } => write!(f, "non-executable_pc-{pc:08x}"),
            CrashReason::RomWrite { pc, addr } => {
                write!(f, "rom-write_pc-{pc:08x}_addr-{addr:08x}")
            }
        }
    }
}

impl LegacyCoverageReport {
    pub fn load_from(path: &Path) -> Result<CoverageReport> {
        bincode::deserialize_from(decoder(path).context("Failed to open report file")?)
            .map(|legacy: Self| CoverageReport {
                name: legacy.name,
                commit: legacy.commit,
                inputs: legacy.inputs,
            })
            .context("Failed to deserialize legacy report")
    }
}

impl CoverageReport {
    pub fn new(name: String) -> Self {
        Self {
            name,
            commit: None,
            inputs: vec![],
        }
    }

    pub fn load_from(path: &Path) -> Result<Self> {
        bincode::deserialize_from(decoder(path).context("Failed to open report file")?)
            .or_else(|_| {
                log::warn!("Failed to deserialize report, trying legacy format...");
                LegacyCoverageReport::load_from(path)
            })
            .context("Failed to deserialize report")
    }

    pub unsafe fn merge(&mut self, report: CoverageReport) {
        self.inputs.extend(report.inputs);
        self.sort_by_timestamp();
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn commit(&self) -> Option<&str> {
        self.commit.as_deref()
    }

    pub fn inputs(&self) -> &[InputCoverage] {
        &self.inputs
    }

    fn add_coverage(&mut self, new: InputCoverage) {
        self.inputs.push(new);
    }

    fn sort_by_timestamp(&mut self) {
        self.inputs
            .sort_by(|a, b| a.timestamp.cmp(&b.timestamp).then(a.id.cmp(&b.id)));
    }
}

impl InputCoverage {
    pub fn new(
        id: InputId,
        timestamp: Epoch,
        stop_reason: StopReason,
        bugs: Option<Vec<Bug>>,
        coverage: FxHashSet<Address>,
    ) -> Self {
        Self {
            id,
            timestamp: Some(timestamp),
            stop_reason,
            bugs,
            coverage,
        }
    }

    pub fn empty_input(coverage: FxHashSet<Address>) -> Self {
        Self {
            id: unsafe { InputId::new(0) },
            timestamp: None,
            stop_reason: StopReason::EndOfInput,
            bugs: None,
            coverage,
        }
    }

    pub fn id(&self) -> InputId {
        self.id
    }

    pub fn timestamp(&self) -> Option<Epoch> {
        self.timestamp
    }

    pub fn stop_reason(&self) -> &StopReason {
        &self.stop_reason
    }

    pub fn bugs(&self) -> Option<&[Bug]> {
        self.bugs.as_deref()
    }

    pub fn crash_reason(&self) -> Option<CrashReason> {
        self.is_crash().then(|| {
            self.bugs
                .clone()
                // bug combination (sorted by name)
                .map(|mut bugs| {
                    bugs.sort();
                    CrashReason::BugCombination(bugs)
                })
                // fallback to crash if no bug was detected
                .unwrap_or_else(|| match self.stop_reason().clone() {
                    StopReason::Crash { pc, ra, .. } => CrashReason::Crash { pc, ra },
                    StopReason::NonExecutable { pc } => CrashReason::NonExecutable { pc },
                    StopReason::RomWrite { pc, addr } => CrashReason::RomWrite { pc, addr },
                    _ => {
                        unreachable!()
                    }
                })
        })
    }

    pub fn coverage(&self) -> &FxHashSet<Address> {
        &self.coverage
    }

    pub fn is_crash(&self) -> bool {
        match self.stop_reason {
            StopReason::EndOfInput => false,
            StopReason::LimitReached(_) | StopReason::InfiniteSleep => false,
            StopReason::ExitHook | StopReason::Script | StopReason::Shutdown => false,
            StopReason::Crash { .. }
            | StopReason::NonExecutable { .. }
            | StopReason::RomWrite { .. } => true,
            StopReason::Reset | StopReason::Panic | StopReason::Abort => false,
            StopReason::UserExitRequest => false,
        }
    }

    pub fn is_valid(&self, bugs_filter: Option<&[&str]>) -> bool {
        // filter by bugs
        if let (Some(bugs), Some(bugs_filter)) = (self.bugs(), bugs_filter) {
            for bug in bugs {
                if bugs_filter.iter().any(|bug_filter| bug == bug_filter) {
                    return false;
                }
            }
        }

        match self.stop_reason {
            StopReason::EndOfInput => true,
            StopReason::LimitReached(_) | StopReason::InfiniteSleep => true,
            StopReason::ExitHook | StopReason::Script | StopReason::Shutdown => true,
            StopReason::Crash { .. }
            | StopReason::NonExecutable { .. }
            | StopReason::RomWrite { .. } => false,
            StopReason::Reset | StopReason::Panic | StopReason::Abort => false,
            StopReason::UserExitRequest => false,
        }
    }
}

pub fn run_cov(
    mut emulator: Emulator,
    config: RunCovConfig,
    coverage: FxHashSet<Address>,
) -> Result<()> {
    // pre-input snapshot
    let pre_input = emulator
        .snapshot_create()
        .context("Failed to create pre-input snapshot")?;

    let mut report = CoverageReport::new(config.name);

    // First MMIO / prefix coverage
    report.add_coverage(InputCoverage::empty_input(coverage));

    for path in config.corpus_paths {
        signal_exit_point()?;

        run_corpus_archive(
            &mut report,
            config.archive.as_ref().cloned(),
            &mut emulator,
            &pre_input,
            &path,
        )?
    }

    // finish report
    report.sort_by_timestamp();

    let mut encoder = encoder(&config.coverage_report).context("Failed to create report file")?;
    bincode::serialize_into(&mut encoder, &report).context("Failed to serialize report")
}

fn run_corpus_archive(
    report: &mut CoverageReport,
    archive: Option<ArchiveBuilder>,
    emulator: &mut Emulator,
    pre_input: &EmulatorSnapshot,
    corpus_path: &Path,
) -> Result<()> {
    log::info!("Loading corpus archive {:?} ...", corpus_path);
    let meta = Archive::from_reader(decoder(corpus_path)?)
        .iter::<CommonEntryKind>()?
        .meta();
    let commit = meta.as_ref().map(|meta| meta.git_version());
    let meta_timestamp = meta.as_ref().map(|meta| meta.timestamp());
    let mut corpus_archive = Archive::from_reader(decoder(corpus_path)?);
    let mut corpus = corpus_archive.iter()?.input_files();
    let mut error = false;

    for entry in corpus.by_ref() {
        signal_exit_point()?;

        let CorpusInputFile {
            timestamp,
            category: _,
            input,
        } = match entry {
            Ok(entry) => entry,
            Err(err) => {
                error = true;
                log::error!("{:?}", err);
                continue;
            }
        };
        let input_id = input.id();

        // relative timestamp
        let relative_timestamp = match meta_timestamp {
            Some(meta_timestamp) if timestamp >= meta_timestamp => timestamp - meta_timestamp,
            Some(meta_timestamp) => {
                log::error!(
                    "Input file timestamp {} earlier then archive meta info timestamp {}",
                    timestamp,
                    meta_timestamp
                );
                timestamp
            }
            None => {
                log::error!("Corpus archive MetaInfo missing");
                timestamp
            }
        };

        // run corpus archive input
        log::info!("Running input {} ...", *input_id);
        let result = emulator.run(input, RunMode::Leaf)?;
        log::info!("Result: {}", result);
        verify_remaining_values(&result);

        // add input file to new archive
        if let Some(archive) = archive.as_ref() {
            write_input_file(
                &mut archive.borrow_mut(),
                &InputResult::new(
                    result.hardware.input,
                    timestamp,
                    result.counts.basic_block(),
                    result.stop_reason.clone(),
                    result.hardware.access_log,
                ),
            )?;
        }

        // add coverage
        report.add_coverage(InputCoverage::new(
            input_id,
            relative_timestamp,
            result.stop_reason,
            result.bugs,
            result.coverage.unwrap(),
        ));

        // restore emuator
        emulator.snapshot_restore(pre_input);
    }

    // set commit
    match (&commit, &report.commit) {
        (Some(commit), Some(old_commit)) if commit != old_commit => {
            log::warn!(
                "Corpus archive with different commit {:?} != {:?}, are you mixing dump files?",
                old_commit,
                commit
            );
        }
        _ => {}
    }
    if let Some(commit) = commit {
        report.commit = Some(commit.to_string());
    }

    // make sure error is visible again at the end
    if error {
        log::error!(
            "Failed to execute all input files in corpus archive {:?}",
            corpus_path
        );
    }

    Ok(())
}
