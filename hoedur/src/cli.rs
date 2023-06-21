use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueHint};
use common::{config::fuzzware, log::LOG_INFO};
use fuzzer::InputCategory;
use modeling::fuzzware::runner::FuzzwareInstallation;

const ARCHIVE: &str = "ARCHIVE";
const INPUT: &str = "INPUT";
const PATH: &str = "PATH";
const REPORT: &str = "REPORT";

#[derive(Parser, Debug)]
#[command(name = "emulator", rename_all = "kebab-case")]
pub struct Arguments {
    /// Target Name used e.g. for (corpus) archive
    #[arg(long, global = true, default_value = "Hoedur", display_order = 1)]
    pub name: String,

    /// Target config file
    #[arg(long, required_unless_present = "import_config", value_hint = ValueHint::FilePath, display_order = 101)]
    pub config: Option<PathBuf>,

    /// Import target config from corpus archive
    #[arg(
        long,
        value_name = ARCHIVE,
        conflicts_with = "config",
        value_hint = ValueHint::FilePath,
        display_order = 102
    )]
    pub import_config: Option<PathBuf>,

    #[command(flatten)]
    pub modeling: ArgumentsModeling,

    #[arg(long, default_value = LOG_INFO, value_hint = ValueHint::FilePath, display_order = 700)]
    pub log_config: PathBuf,

    #[command(flatten)]
    pub debug: ArgumentsDebug,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
#[command(rename_all = "kebab-case")]
pub enum Command {
    /// Run input file(s)
    #[command(name = "run")]
    Run(RunArguments),

    /// Run input file(s) / corpus archive(s) and collect coverage report
    #[command(name = "run-cov")]
    RunCov(RunCovArguments),

    /// Run inputs in corpus archive
    #[command(name = "run-corpus")]
    RunCorpusArchive(RunCorpusArchiveArguments),

    /// Fuzz target with Hödur
    #[command(name = "fuzz")]
    Fuzz(HoedurArguments),
}

#[derive(Args, Debug)]
#[command(rename_all = "kebab-case")]
pub struct RunArguments {
    #[command(flatten)]
    pub prefix: ArgumentsPrefixInput,

    #[command(flatten)]
    pub archive: Archive,

    /// Path to the input files
    #[arg(value_name = INPUT, value_hint = ValueHint::FilePath, display_order = 20)]
    pub input_files: Vec<PathBuf>,

    /// Write coverage bitmap to dir
    #[arg(long, value_name = PATH, value_hint = ValueHint::DirPath, display_order = 720)]
    pub bitmap_dir: Option<PathBuf>,
}

#[derive(Args, Debug)]
#[command(rename_all = "kebab-case")]
pub struct RunCovArguments {
    #[command(flatten)]
    pub prefix: ArgumentsPrefixInput,

    #[command(flatten)]
    pub archive: Archive,

    /// Coverage report output path
    #[arg(value_name = REPORT, value_hint = ValueHint::FilePath, display_order = 22)]
    pub coverage_report: PathBuf,

    /// Path to the corpus archives files / corpus dir
    #[arg(value_name = "PATH|ARCHIVE", value_hint = ValueHint::AnyPath, display_order = 24)]
    pub corpus_paths: Vec<PathBuf>,
}

#[derive(Args, Debug)]
#[command(rename_all = "kebab-case")]
pub struct RunCorpusArchiveArguments {
    #[command(flatten)]
    pub prefix: ArgumentsPrefixInput,

    #[command(flatten)]
    pub archive: Archive,

    #[command(flatten)]
    pub input_filter: InputFilter,

    /// Path to the corpus archive file
    #[arg(value_name = ARCHIVE, value_hint = ValueHint::FilePath, display_order = 20)]
    pub corpus_archive: PathBuf,

    /// Write coverage bitmap to dir
    #[arg(long, value_name = PATH, value_hint = ValueHint::DirPath, display_order = 710)]
    pub bitmap_dir: Option<PathBuf>,
}

#[derive(Args, Debug)]
#[command(rename_all = "kebab-case")]
pub struct HoedurArguments {
    #[command(flatten)]
    pub prefix: ArgumentsPrefixInput,

    #[command(flatten)]
    pub archive_dir: ArchiveDir,

    /// Use seed for a deterministic fuzzing run
    #[arg(long, value_name = PATH, value_hint = ValueHint::FilePath, display_order = 120)]
    pub seed: Option<PathBuf>,

    /// Enable snapshot fuzzing
    #[arg(long, display_order = 150)]
    pub snapshots: bool,

    #[command(flatten)]
    pub statistics: ArgumentsStatistics,

    /// Path to corpus archive(s) to import
    #[arg(long, value_name = ARCHIVE, value_hint = ValueHint::FilePath, display_order = 104)]
    pub import_corpus: Vec<PathBuf>,
}

#[derive(Args, Debug)]
#[command(rename_all = "kebab-case")]
pub struct Archive {
    /// Write archive including config, inputs and statistics
    #[arg(long, display_order = 10)]
    pub write_archive: bool,

    #[command(flatten)]
    pub archive_dir: ArchiveDir,
}

#[derive(Args, Debug)]
#[command(rename_all = "kebab-case")]
pub struct ArchiveDir {
    /// Write archive including config, inputs and statistics
    #[arg(
        long,
        global = true,
        alias = "corpus-dir",
        value_name = PATH,
        default_value = "./corpus",
        value_hint = ValueHint::DirPath,
        display_order = 11
    )]
    pub archive_dir: PathBuf,
}

#[derive(Args, Debug)]
#[command(rename_all = "kebab-case")]
pub struct ArgumentsPrefixInput {
    /// Path to the file containing the prefix input that is prepended
    #[arg(long, value_name = INPUT, num_args = 1, value_hint = ValueHint::FilePath, display_order = 2)]
    pub prefix_input: Vec<PathBuf>,
}

#[derive(Args, Debug)]
#[command(rename_all = "kebab-case")]
pub struct ArgumentsModeling {
    /// Load existing MMIO models
    #[arg(long, conflicts_with = "import_config", value_hint = ValueHint::FilePath, display_order = 201)]
    pub models: Option<PathBuf>,

    /// Enable on-demand fuzzware model creation
    #[arg(long, display_order = 210)]
    pub fuzzware: bool,

    /// Share fuzzware models with other instances
    #[arg(long, value_name = PATH, value_name = PATH, value_hint = ValueHint::DirPath, display_order = 211)]
    pub model_share: Option<PathBuf>,

    /// Fuzzware installation
    #[arg(
        long,
        value_name = "INSTALL",
        default_value = "auto",
        display_order = 212
    )]
    pub fuzzware_installation: FuzzwareInstallation,

    /// Fuzzware (local) binary
    #[arg(long, value_name = "BINARY", value_hint = ValueHint::CommandName, default_value = fuzzware::DEFAULT_LOCAL_BINARY, display_order = 215)]
    pub fuzzware_binary: PathBuf,

    /// Docker binary
    #[arg(long, value_name = "BINARY", value_hint = ValueHint::CommandName, default_value = fuzzware::DEFAULT_DOCKER_BINARY, display_order = 220)]
    pub docker_binary: PathBuf,

    /// Fuzzware docker image
    #[arg(long, value_name = "IMAGE", default_value = fuzzware::DEFAULT_DOCKER_IMAGE, display_order = 221)]
    pub fuzzware_docker_image: String,

    /// Fuzzware docker image tag
    #[arg(long, value_name = "TAG", default_value = fuzzware::DEFAULT_DOCKER_TAG, display_order = 222)]
    pub fuzzware_docker_tag: String,
}

#[derive(Args, Debug)]
#[command(rename_all = "kebab-case")]
pub struct ArgumentsStatistics {
    /// Enable statistics functions
    #[arg(long, display_order = 301)]
    pub statistics: bool,
}

#[derive(Args, Debug)]
#[command(rename_all = "kebab-case")]
pub struct InputFilter {
    /// Filter input files in corpus archive by (original) input category, skip others.
    #[arg(long, value_name = "CATEGORY", num_args = 1, display_order = 301)]
    pub filter_category: Vec<InputCategory>,
}

#[derive(Args, Debug, Default)]
#[command(rename_all = "kebab-case")]
pub struct ArgumentsDebug {
    /// Enable debug functions (may slow down fuzzing)
    #[arg(long, display_order = 701)]
    pub debug: bool,

    /// Hook every basic-block (huge performance impact)
    #[arg(long, display_order = 720)]
    pub trace: bool,

    /// Write trace to file path
    #[arg(
        long,
        value_name = "TRACE",
        requires = "debug",
        requires = "trace",
        value_hint = ValueHint::FilePath,
        display_order = 721
    )]
    pub trace_file: Option<PathBuf>,

    /// Custom hook script
    #[arg(long = "hook", value_name = "HOOK", num_args = 1, value_hint = ValueHint::FilePath, display_order = 730)]
    pub hooks: Vec<PathBuf>,
}
