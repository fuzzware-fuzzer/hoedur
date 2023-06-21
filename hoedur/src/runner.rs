use std::{
    fmt::Debug,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use archive::{write_config, write_file_storage, Archive, ArchiveBuilder};
use common::{
    exit::signal_exit_point,
    file_storage::FileStorage,
    fs::{decoder, decoder_slice, find_files, modify_time},
    FxHashMap,
};
use emulator::{
    archive::{EmulatorEntry, EmulatorEntryKind},
    EmulatorConfig, EmulatorDebugConfig, EmulatorLimits, ExecutionResult, RunMode, StopReason,
};
use fuzzer::{
    write_input_file, CorpusEntry, CorpusEntryKind, InputCategory, InputResult, IntoInputFileIter,
};
use modeling::{
    archive::{ModelingEntry, ModelingEntryKind},
    fuzzware::runner::FuzzwareRunner,
    input::InputFile,
    mmio::Mmio,
    modeling::Modeling,
};

use crate::{
    archive::{create_archive, opt_archive},
    cli,
    coverage::{run_cov, RunCovConfig},
    hoedur::{self, HoedurConfig},
    Emulator,
};

#[derive(Debug)]
pub struct RunnerConfig {
    file_storage: FileStorage,
    emulator: EmulatorConfig,
    modeling: Modeling,
    command: Command,
}

#[derive(Debug)]
pub struct RunConfig {
    archive: Option<ArchiveBuilder>,
    prefix_input: Vec<PathBuf>,
    inputs: Vec<PathBuf>,
    bitmap_dir: Option<PathBuf>,
}

impl RunConfig {
    pub fn new(
        archive: Option<ArchiveBuilder>,
        prefix_input: Vec<PathBuf>,
        inputs: Vec<PathBuf>,
        bitmap_dir: Option<PathBuf>,
    ) -> Self {
        Self {
            archive,
            prefix_input,
            inputs,
            bitmap_dir,
        }
    }

    pub fn from_cli(name: &str, args: cli::RunArguments) -> Result<Self> {
        Ok(Self::new(
            opt_archive(&args.archive)
                .map(|archive_dir| create_archive(name, archive_dir))
                .transpose()?,
            args.prefix.prefix_input,
            args.input_files,
            args.bitmap_dir,
        ))
    }
}

#[derive(Debug)]
pub struct RunCorpusArchiveConfig {
    archive: Option<ArchiveBuilder>,
    category_filter: Option<Vec<InputCategory>>,
    prefix_input: Vec<PathBuf>,
    bitmap_dir: Option<PathBuf>,
    corpus_archive: PathBuf,
}

impl RunCorpusArchiveConfig {
    pub fn new(
        archive: Option<ArchiveBuilder>,
        category_filter: Option<Vec<InputCategory>>,
        prefix_input: Vec<PathBuf>,
        bitmap_dir: Option<PathBuf>,
        corpus_archive: PathBuf,
    ) -> Self {
        Self {
            archive,
            category_filter,
            prefix_input,
            bitmap_dir,
            corpus_archive,
        }
    }

    pub fn from_cli(name: &str, args: cli::RunCorpusArchiveArguments) -> Result<Self> {
        let category_filter = args.input_filter.filter_category;

        Ok(Self::new(
            opt_archive(&args.archive)
                .map(|archive_dir| create_archive(name, archive_dir))
                .transpose()?,
            (!category_filter.is_empty()).then_some(category_filter),
            args.prefix.prefix_input,
            args.bitmap_dir,
            args.corpus_archive,
        ))
    }
}

#[derive(Debug)]
pub enum Command {
    Run(RunConfig),
    RunCov(RunCovConfig),
    RunCorpusArchive(RunCorpusArchiveConfig),
    Fuzzer(HoedurConfig),
}

impl Command {
    pub fn archive(&self) -> Option<ArchiveBuilder> {
        match &self {
            Command::Run(RunConfig { archive, .. })
            | Command::RunCov(RunCovConfig { archive, .. })
            | Command::RunCorpusArchive(RunCorpusArchiveConfig { archive, .. }) => {
                archive.as_ref().cloned()
            }
            Command::Fuzzer(HoedurConfig { archive, .. }) => Some(archive.clone()),
        }
    }

    pub fn prefix_inputs(&self) -> &[PathBuf] {
        match &self {
            Command::Run(RunConfig { prefix_input, .. })
            | Command::RunCov(RunCovConfig { prefix_input, .. })
            | Command::RunCorpusArchive(RunCorpusArchiveConfig { prefix_input, .. })
            | Command::Fuzzer(HoedurConfig { prefix_input, .. }) => prefix_input,
        }
    }
}

impl RunnerConfig {
    pub fn new(
        file_storage: FileStorage,
        emulator: EmulatorConfig,
        modeling: Modeling,
        command: Command,
    ) -> Self {
        Self {
            file_storage,
            emulator,
            modeling,
            command,
        }
    }

    pub fn from_cli(args: cli::Arguments) -> Result<Self> {
        let (mut file_storage, mmio) = match args.import_config {
            // import config from existing corpus archive
            Some(path) => import_config(path)?,
            None => {
                // target config file
                let target_config = args
                    .config
                    .expect("--config must be present when --import-config is missing");
                if !target_config.is_file() {
                    bail!("Target Config file {:?} does not exist", target_config);
                }

                // file storage with filesystem access
                (FileStorage::new(target_config)?, vec![])
            }
        };

        // force enable debug for coverage
        let (debug_enabled, trace, coverage) = if let cli::Command::RunCov(_) = &args.command {
            if !args.debug.debug {
                log::info!("Enabled debug mode for gathering coverage");
            }
            if !args.debug.trace {
                log::info!("Enabled trace mode for gathering coverage");
            }

            (true, true, true)
        } else {
            (args.debug.debug, args.debug.trace, false)
        };

        // debug config
        let debug = EmulatorDebugConfig::new(
            debug_enabled,
            trace,
            args.debug.trace_file,
            coverage,
            args.debug.hooks,
        );

        // emulator config
        let emulator_config = EmulatorConfig::read_from(&mut file_storage, debug)?;

        // parse command cli options
        let name = args.name;
        let command = match args.command {
            cli::Command::Run(args) => Command::Run(RunConfig::from_cli(&name, args)?),
            cli::Command::RunCov(args) => Command::RunCov(RunCovConfig::from_cli(&name, args)?),
            cli::Command::RunCorpusArchive(args) => {
                Command::RunCorpusArchive(RunCorpusArchiveConfig::from_cli(&name, args)?)
            }
            cli::Command::Fuzz(args) => Command::Fuzzer(HoedurConfig::from_cli(name, args)?),
        };

        // modeling
        let mut modeling = if let Some(archive) = command.archive() {
            Modeling::with_archive(archive)
        } else {
            Modeling::default()
        };

        // enable fuzzware
        if args.modeling.fuzzware {
            modeling.set_fuzzware(
                FuzzwareRunner::new(
                    args.modeling.fuzzware_installation,
                    args.modeling.fuzzware_binary,
                    args.modeling.docker_binary,
                    args.modeling.fuzzware_docker_image,
                    args.modeling.fuzzware_docker_tag,
                ),
                args.modeling.model_share,
            )?;
        }

        // load models
        modeling
            .append_models(mmio)
            .context("Failed to append imported MMIO models")?;
        if let Some(path) = args.modeling.models {
            file_storage.read_from_fs(&path)?;
            file_storage
                .get(&path)
                .and_then(|content| modeling.load_models(decoder_slice(content)?))
                .with_context(|| format!("Failed to load MMIO models from {path:?}"))?;
        }

        Ok(Self::new(file_storage, emulator_config, modeling, command))
    }
}

fn import_config(path: PathBuf) -> Result<(FileStorage, Vec<Mmio>)> {
    // open corpus archive
    log::info!("Importing emulator config from archive {:?} ...", path);
    let mut archive = Archive::from_reader(decoder(&path)?);
    let missing = |name| format!("'{name}' missing in corpus archive {path:?}");

    // read config files from corpus archive
    let mut target_config = None;
    let mut mmio = vec![];
    let mut filemap = None;
    let mut files = FxHashMap::default();
    for entry in archive.iter()? {
        let mut entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                log::error!("{:?}", err);
                continue;
            }
        };

        // parse archive entries
        if matches!(
            entry.kind(),
            Some(
                CorpusEntryKind::Emulator(
                    EmulatorEntryKind::TargetConfig
                        | EmulatorEntryKind::MmioModels
                        | EmulatorEntryKind::FileMap
                        | EmulatorEntryKind::ConfigFile
                ) | CorpusEntryKind::Modeling(ModelingEntryKind::MmioModel)
            )
        ) {
            let entry = match entry.parse_entry() {
                Some(Ok(entry)) => entry,
                Some(Err(err)) => {
                    log::error!("Failed to parse archive entry: {:?}", err);
                    continue;
                }
                _ => unreachable!(),
            };

            match entry {
                CorpusEntry::Emulator(EmulatorEntry::TargetConfig(data)) => {
                    target_config = Some(data)
                }
                CorpusEntry::Emulator(EmulatorEntry::MmioModels(mut models)) => {
                    // TODO: remove legacy model loading
                    log::warn!(
                        "This archive config contains a legacy MMIO models file: {:?}",
                        "config/models.yml.zst"
                    );
                    mmio.append(&mut models)
                }
                CorpusEntry::Emulator(EmulatorEntry::FileMap(data)) => filemap = Some(data),
                CorpusEntry::Emulator(EmulatorEntry::ConfigFile(filepath, content)) => {
                    log::debug!("Loading file {:?} from archive {:?} ...", filepath, path);
                    files.insert(filepath, content);
                }
                CorpusEntry::Modeling(ModelingEntry::MmioModel(model)) => mmio.push(model),
                _ => unreachable!(),
            }
        }
    }

    // collect config files into file storage
    let filemap = filemap.with_context(|| missing("config/filemap.yml"))?;
    let files: FxHashMap<_, _> = filemap
        .into_iter()
        .map(|(filepath, archive_path)| {
            files
                .remove(&archive_path)
                .with_context(|| format!("{archive_path:?} missing in corpus archive {path:?}"))
                .map(|content| (filepath, content))
        })
        .collect::<Result<_>>()?;

    // target config file
    let target_config = target_config
        .with_context(|| missing("config/target-config.txt"))
        .context("Failed to load target config")?;

    FileStorage::with_files(target_config, files)
        .context("Failed to create file storage")
        .map(|file_storage| (file_storage, mmio))
}

pub fn run(config: RunnerConfig) -> Result<()> {
    // load prefix inputs
    let mut config = config;
    for prefix_input in config.command.prefix_inputs() {
        config
            .file_storage
            .read(prefix_input)
            .with_context(|| format!("Failed to read prefix input {prefix_input:?}"))?;
    }
    let config = config;

    // add file storage to archive
    if let Some(archive) = config.command.archive() {
        write_config(&mut archive.borrow_mut()).context("Failed to write config to archive")?;
        write_file_storage(&mut archive.borrow_mut(), &config.file_storage)
            .context("Failed to write file storage to archive")?;
    }

    // create emulator
    let mut emulator = Emulator::new(&config.file_storage, config.emulator, config.modeling)
        .context("Failed to create emulator")?;

    // set exit signal hook
    qemu_rs::set_signal_handler()?;

    // run until first MMIO read
    log::info!("Running until first MMIO read from input ...");
    emulator.set_next_input_limits(EmulatorLimits::new());
    let result = emulator
        .run(InputFile::default(), RunMode::Normal)
        .context("run emulator with empty input")?;
    log::info!("Result: {}", result);
    let mut coverage = result.coverage;

    // config sanity check
    match result.stop_reason {
        StopReason::EndOfInput => {
            log::info!("First MMIO read from input found.");
        }
        reason => {
            anyhow::bail!(
                "Could not run until first MMIO read: {:x?}. Please check your target config.",
                reason
            );
        }
    }

    for prefix_input in config.command.prefix_inputs() {
        log::info!("Running prefix input {:?}...", prefix_input);
        emulator.set_next_input_limits(EmulatorLimits::new());

        let content = config.file_storage.get(prefix_input)?;
        let input = InputFile::read_from_slice(content)
            .with_context(|| format!("Failed to deserialize prefix input file {prefix_input:?}"))?;
        let result = emulator
            .run(input, RunMode::Normal)
            .context("run emulator")?;
        log::info!("Result: {}", result);

        // prefix input sanity check
        match result.stop_reason {
            StopReason::EndOfInput => {
                if result.hardware.input.remaining_values() > 0 {
                    log::warn!(
                        "Prefix input run until end with {} remaining bytes/values",
                        result.hardware.input.remaining_values()
                    );
                } else {
                    log::info!("Prefix input run until end.");
                }
            }
            reason => {
                bail!(
                    "Could not run prefix input until end: {:x?}. You may want to check your target config / input prefix.",
                    reason
                );
            }
        }

        // collect coverage
        if let (Some(coverage), Some(prefix_coverage)) = (&mut coverage, result.coverage) {
            coverage.extend(&prefix_coverage)
        }
    }

    // offset limits by current counts
    emulator.offset_limits();

    // drop no longer needed file storage
    std::mem::drop(config.file_storage);

    // run input / fuzzer
    match config.command {
        Command::Run(run_config) => run_inputs(emulator, run_config),
        Command::RunCov(cov_config) => {
            run_cov(emulator, cov_config, coverage.context("missing coverage")?)
        }
        Command::RunCorpusArchive(corpus_config) => run_corpus_archive(emulator, corpus_config),
        Command::Fuzzer(hoedur_config) => hoedur::run_fuzzer(emulator, hoedur_config),
    }?;

    log::info!("end of execution");
    Ok(())
}

fn run_inputs(mut emulator: Emulator, config: RunConfig) -> Result<()> {
    // pre-input snapshot
    let pre_input = emulator
        .snapshot_create()
        .context("Failed to create pre-input snapshot")?;

    for path in config.inputs {
        // paths either file or dir of files
        let inputs = if path.is_file() {
            vec![path]
        } else if path.is_dir() {
            find_files(&path, None, None)?
        } else {
            bail!("{:?} is neither a dir nor a file", path);
        };

        for input_path in inputs {
            signal_exit_point()?;

            emulator.snapshot_restore(&pre_input);

            let result = run_input(
                &mut emulator,
                &input_path,
                RunMode::Leaf,
                config.bitmap_dir.as_deref(),
            )?;

            // add input file to new corpus
            if let Some(archive) = config.archive.as_ref() {
                write_input_file(
                    &mut archive.borrow_mut(),
                    &InputResult::new(
                        result.hardware.input,
                        modify_time(&input_path)?,
                        result.counts.basic_block(),
                        result.stop_reason,
                        result.hardware.access_log,
                    ),
                )?;
            }
        }
    }

    Ok(())
}

fn run_input(
    emulator: &mut Emulator,
    input: &Path,
    mode: RunMode,
    bitmap_dir: Option<&Path>,
) -> Result<ExecutionResult<InputFile>> {
    // run input
    log::info!("Running input {:?} ...", input);
    let result = emulator.run(InputFile::read_from_path(input)?, mode)?;
    verify_remaining_values(&result);

    log::info!("Result: {}", result);
    write_bitmap(bitmap_dir, *result.hardware.input.id())?;

    Ok(result)
}

fn run_corpus_archive(mut emulator: Emulator, config: RunCorpusArchiveConfig) -> Result<()> {
    // pre-input snapshot
    let pre_input = emulator
        .snapshot_create()
        .context("Failed to create pre-input snapshot")?;

    log::info!("Loading corpus archive {:?} ...", config.corpus_archive);
    let mut corpus_archive = Archive::from_reader(decoder(&config.corpus_archive)?);
    let corpus = corpus_archive.iter()?.input_files();

    let mut error = false;
    let mut stop_reasons: FxHashMap<_, FxHashMap<Vec<_>, Vec<_>>> = FxHashMap::default();

    for entry in corpus {
        signal_exit_point()?;

        // get input
        let (input, category, timestamp) = match entry {
            Ok(entry) => (entry.input, entry.category, entry.timestamp),
            Err(err) => {
                error = true;
                log::error!("{:?}", err);
                continue;
            }
        };
        let input_id = input.id();

        // apply input category filter
        if let Some(input_filter) = &config.category_filter {
            if !input_filter.contains(&category) {
                log::debug!("Skiping input {} in category {:?}", *input_id, category);
                continue;
            }
        }

        // run input
        log::info!("Running input {} ...", *input_id);
        let result = emulator.run(input, RunMode::Leaf)?;
        log::trace!("result = {:#x?}", result);
        log::info!("Result: {}", result);
        write_bitmap(config.bitmap_dir.as_deref(), *result.hardware.input.id())?;

        // add input file to new archive
        if let Some(archive) = config.archive.as_ref() {
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

        // collect input id's grouped by stop reason + bugs
        stop_reasons
            .entry(result.stop_reason)
            .or_default()
            .entry(result.bugs.unwrap_or_default())
            .or_default()
            .push(input_id);

        // restore emuator
        emulator.snapshot_restore(&pre_input);
    }

    // log stop reason, bugs : input summary
    log::info!("Input Summary:");
    for (stop_reason, bugs_inputs) in stop_reasons {
        for (bugs, inputs) in bugs_inputs {
            log::info!(
                "{:x?}, Bugs {:?}: {}",
                stop_reason,
                bugs,
                inputs
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }
    }

    if error {
        log::error!(
            "Failed to execute all input files in corpus archive {:?}",
            config.corpus_archive
        );
    }

    Ok(())
}

fn write_bitmap(bitmap_dir: Option<&Path>, input_id: usize) -> Result<()> {
    if let Some(dir) = &bitmap_dir {
        let bitmap = dir.join(format!("bitmap-{input_id}.raw"));
        qemu_rs::coverage::get_coverage_bitmap().write_to(&bitmap)?;
        log::info!("Wrote bitmap to {:?}", bitmap);
    }

    Ok(())
}

pub(crate) fn verify_remaining_values(result: &ExecutionResult<InputFile>) {
    // verify read to end
    let remaining = result.hardware.input.remaining_values();
    if remaining > 0 {
        let level = match InputCategory::from(&result.stop_reason) {
            InputCategory::Input => log::Level::Warn,
            _ => log::Level::Info,
        };
        log::log!(
            level,
            "input file not read until end: {} value(s) remaining",
            remaining
        );
    }
}
