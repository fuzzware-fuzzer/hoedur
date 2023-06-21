use std::{fmt, io, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use common::{
    hashbrown::hash_map::Entry,
    log::{init_log, LOG_INFO},
    FxHashMap,
};
use hoedur::coverage::CoverageReport;
use modeling::input::InputId;
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(name = "hoedur-eval-crash")]
struct Arguments {
    #[arg(long, default_value = LOG_INFO)]
    log_config: PathBuf,

    #[arg(long)]
    yaml: bool,

    reports: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
struct CrashTime {
    time: u64,
    source: CrashSource,
}

#[derive(Debug, Clone, Serialize)]
struct CrashSource {
    input: InputId,
    report: Option<String>,
}

impl fmt::Display for CrashTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:>7} s", self.time)
    }
}

impl fmt::Display for CrashSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Input {}", self.input)?;

        if let Some(report) = &self.report {
            write!(f, " ({report})")
        } else {
            Ok(())
        }
    }
}

fn main() -> Result<()> {
    let opt = Arguments::parse();

    init_log(&opt.log_config)?;
    log::trace!("Args: {:#?}", opt);

    let mut crashes = FxHashMap::default();

    for path in opt.reports {
        log::info!("Loading coverage report {:?} ...", path);
        let report = match CoverageReport::load_from(&path) {
            Ok(report) => report,
            Err(err) => {
                log::error!("Failed to load coverage report {:?}: {:?}", path, err);
                continue;
            }
        };

        // find first occurrence for each crash
        for input in report.inputs() {
            // collect crash reason
            let reason = match input.crash_reason() {
                Some(reason) => reason,
                None => {
                    continue;
                }
            };

            // get meta info
            let time = match input.timestamp() {
                Some(time) => time,
                None => {
                    log::debug!("skipping input {} without timestamp", input.id());
                    continue;
                }
            };
            let source = || CrashSource {
                input: input.id(),
                report: path
                    .file_name()
                    .map(|filename| filename.to_string_lossy().to_string()),
            };

            match crashes.entry(reason) {
                Entry::Vacant(entry) => {
                    entry.insert(CrashTime {
                        time,
                        source: source(),
                    });
                }
                Entry::Occupied(entry) => {
                    let crash_time = entry.into_mut();
                    if time < crash_time.time {
                        crash_time.time = time;
                        crash_time.source = source();
                    }
                }
            }
        }
    }

    // sort by crash time
    let mut crashes: Vec<_> = crashes.into_iter().collect();
    crashes.sort_by(|a, b| a.1.time.cmp(&b.1.time));

    // print crashes with time
    if opt.yaml {
        serde_yaml::to_writer(io::stdout(), &crashes).context("Failed to serialize crashes")
    } else {
        for (crash, crash_time) in crashes {
            println!("{} : {:x?} :\t {}", crash_time, crash, crash_time.source);
        }

        Ok(())
    }
}
