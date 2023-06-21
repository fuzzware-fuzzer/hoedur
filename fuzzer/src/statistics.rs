use std::{
    fmt,
    time::{Duration, Instant},
};

use anyhow::Result;
use cli_table::Table;
use common::{
    config::statistics::*,
    time::{epoch, Epoch},
    FxHashMap,
};
use derive_more::{Add, AddAssign, Sub, SubAssign};
use emulator::{EmulatorCounts, StopReason};
use modeling::input::{InputContext, InputFile, InputId};
use num_format::{Locale, ToFormattedString};
use serde::{Deserialize, Serialize};

use crate::{
    corpus::{Corpus, CorpusResultKind},
    InputResult,
};
pub use crate::{
    corpus::{InputCategory, StreamInfo},
    coverage::Feature,
    mutation::{MutationLog, MutationMode, Mutator, MutatorKind, MutatorVariant, Random},
    stream_distribution::StreamRandomDistribution,
};

#[derive(Debug)]
pub struct Statistics {
    enabled: bool,
    executions: usize,
    minimizations: usize,
    counts: EmulatorCounts,
    new_coverage: bool,
    last_update: Instant,
    last_executions: usize,
    last_minimizations: usize,
    last_counts: EmulatorCounts,
    executions_history: Option<Vec<ExecutionsHistory>>,
    input_size_history: Option<Vec<InputSizeHistory>>,
    fuzzer: Option<FuzzerStatistics>,
}

#[derive(Debug, Default, Clone, Add, AddAssign, Sub, SubAssign, Serialize, Deserialize)]
pub struct ExecutionsHistory {
    pub interval: Duration,
    pub new_executions: usize,
    pub new_minimizations: usize,
    pub new_counts: EmulatorCounts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputSizeHistory {
    pub timestamp: Epoch,
    pub input_id: InputId,
    pub input_len: usize,
    pub input_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticsHistory {
    pub timestamp: Epoch,
    pub corpus: Option<CorpusStatistics>,
    pub fuzzer: Option<FuzzerStatistics>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FuzzerStatistics {
    pub fuzzer_name: String,
    pub stop_reason: FxHashMap<StopReason, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusStatistics {
    pub edges: usize,
    pub features: Vec<(Feature, u16)>,
    pub rare_features: Vec<Feature>,
    pub unscheduled_features: Vec<Feature>,
    pub most_abundant_rare_feature_frequency: u16,
    pub mutation_count: usize,
    pub inputs: Vec<InputStatistics>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Table)]
pub struct InputStatistics {
    pub id: InputId,
    pub category: InputCategory,
    pub length: usize,
    pub uniq_features: usize,
    #[table(skip)]
    pub rare_feature_frequency: FxHashMap<Feature, u16>,
    #[table(skip)]
    pub stream_info: StreamInfo,
    pub mutation_count: usize,
    #[table(skip)]
    pub child_results: [usize; InputCategory::VALID_VARIANT_COUNT],
    pub weight: f64,
}

#[derive(Debug, Clone)]
pub struct StatisticsInfo {
    pub input_id: InputId,
    pub input_len: usize,
    pub input_bytes: usize,
    pub input_remaining_values: usize,
    pub input_parent: Option<InputId>,
    pub stop_reason: StopReason,
    pub mutation_chain_len: usize,
    pub read_limit: Option<usize>,
}

impl fmt::Display for CorpusStatistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Corpus has {:>6} {:<10} ({:>3} rare features, {:>3} unscheduled features, most abundant feature frequency: {:>5})",
            self.features.len(),
            "features",
            self.rare_features.len(),
            self.unscheduled_features.len(),
            self.most_abundant_rare_feature_frequency
        )?;
        writeln!(f, "{:>17} {:<10}", self.edges, "edges")?;
        write!(f, "{:>17} {:<10}", self.inputs.len(), "inputs",)?;
        write!(f, "{:>17} {:<10}", self.mutation_count, "executions")
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MutationDetails {
    pub mode: MutationMode,
    pub distribution: Option<StreamRandomDistribution>,
    pub stream: InputContext,
    pub mutator: MutatorKind,
    pub mutator_variant: MutatorVariant,
}

impl From<&MutationLog> for MutationDetails {
    fn from(log: &MutationLog) -> Self {
        Self {
            mode: log.mode,
            distribution: log.distribution,
            stream: log.mutation.target().context.clone(),
            mutator: log.mutation.mutator(),
            mutator_variant: log.mutation.mutator_variant(),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SuccessRate {
    pub count: usize,
    pub success: usize,
}

impl StatisticsInfo {
    pub fn from_input(
        input: &InputFile,
        stop_reason: StopReason,
        mutation_chain_len: usize,
    ) -> Self {
        Self {
            input_id: input.id(),
            input_len: input.len(),
            input_bytes: input.bytes(),
            input_remaining_values: input.remaining_values(),
            input_parent: input.parent(),
            stop_reason,
            mutation_chain_len,
            read_limit: None,
        }
    }

    pub fn update_input(&mut self, result: &InputResult) {
        self.input_len = result.file().len();
        self.input_bytes = result.file().bytes();
        self.input_remaining_values = result.file().remaining_values();
    }
}

impl fmt::Display for FuzzerStatistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Fuzzer: {}", self.fuzzer_name)?;

        write!(f, "    stop reasons:")?;
        let mut crashes = 0;
        for (reason, count) in &self.stop_reason {
            match reason {
                StopReason::Crash { .. } | StopReason::NonExecutable { .. } => {
                    crashes += count;
                }
                _ => {
                    write!(f, "\n        {:<30}: {:>12}", format!("{reason:x?}"), count)?;
                }
            }
        }

        if crashes > 0 {
            write!(f, "\n        {:<30}: {:>12}", "Crash", crashes)?;
        }

        Ok(())
    }
}

impl fmt::Debug for FuzzerStatistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Fuzzer: {}", self.fuzzer_name)?;

        writeln!(f, "{:<4}stop reasons:", "")?;
        for (reason, count) in &self.stop_reason {
            writeln!(f, "{:<8}{:<30} : {:>12}", "", format!("{reason:x?}"), count)?;
        }

        Ok(())
    }
}

impl fmt::Debug for MutationDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Mode:Distribution
        write!(
            f,
            "{:<15} ",
            match self.distribution {
                Some(dist) => format!("{:?}:{:?}", self.mode, dist),
                None => format!("{:?}", self.mode),
            }
        )?;

        // stream context + value type
        write!(
            f,
            "{:>28}, {:<10} ",
            self.stream.context().to_padded_string(),
            format!("{:?}", self.stream.value_type())
        )?;

        // mutator + variant
        write!(
            f,
            "{:<42}",
            match &self.mutator_variant {
                MutatorVariant::None => format!("{:?}", self.mutator),
                variant => format!("{:?}:{:?}", self.mutator, variant),
            }
        )
    }
}

impl fmt::Display for SuccessRate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "count: {:>15}",
            self.count.to_formatted_string(&Locale::en)
        )?;

        write_permile(f, "success", self.success, self.count)?;

        Ok(())
    }
}

fn write_permile(
    f: &mut fmt::Formatter,
    name: &str,
    count: usize,
    max_count: usize,
) -> fmt::Result {
    write!(
        f,
        ", {}: {:>15} ({:>10.5}‰)",
        name,
        count.to_formatted_string(&Locale::en),
        count as f64 / max_count as f64 * 1_000.
    )
}

impl Statistics {
    pub fn new(fuzzer_name: String, enabled: bool) -> Self {
        Self {
            enabled,
            executions: 0,
            minimizations: 0,
            counts: EmulatorCounts::default(),
            new_coverage: false,
            last_update: Instant::now(),
            last_executions: 0,
            last_minimizations: 0,
            last_counts: EmulatorCounts::default(),
            executions_history: EXECUTIONS_HISTORY.then(Vec::new),
            input_size_history: INPUT_SIZE_HISTORY.then(Vec::new),
            fuzzer: enabled.then(|| FuzzerStatistics::new(fuzzer_name)),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn fuzzer(&self) -> Option<&FuzzerStatistics> {
        self.fuzzer.as_ref()
    }

    pub fn executions(&self) -> Option<&[ExecutionsHistory]> {
        self.executions_history.as_deref()
    }

    pub fn input_size(&self) -> Option<&[InputSizeHistory]> {
        self.input_size_history.as_deref()
    }

    pub fn process_result<'a>(
        &mut self,
        info: Option<StatisticsInfo>,
        result: CorpusResultKind,
        corpus: &Corpus,
    ) -> Result<()> {
        let new_coverage = matches!(result, CorpusResultKind::NewCoverage);
        self.executions += 1;
        self.new_coverage |= new_coverage;

        // print stats
        let update_diff = Instant::now() - self.last_update;
        if (self.new_coverage && update_diff > MIN_UPDATE_INTERVAL)
            || (update_diff > MAX_UPDATE_INTERVAL)
        {
            // calculate execs diff
            let history = ExecutionsHistory {
                interval: update_diff,
                new_executions: self.executions - self.last_executions,
                new_minimizations: self.minimizations - self.last_minimizations,
                new_counts: self.counts.clone() - self.last_counts.clone(),
            };

            // current speed
            let time_diff = update_diff.as_secs_f32();
            let executions = (history.new_executions as f32 / time_diff) as usize;
            let minimizations = (history.new_minimizations as f32 / time_diff) as usize;
            let counts = EmulatorCounts::new(
                (history.new_counts.basic_block() as f32 / time_diff) as usize,
                (history.new_counts.interrupt() as f32 / time_diff) as usize,
                (history.new_counts.mmio_read() as f32 / time_diff) as usize,
                (history.new_counts.mmio_write() as f32 / time_diff) as usize,
            );

            // print fuzzer / basic statistics
            if let Some(fuzzer) = self.fuzzer() {
                log::info!(
                    "{:>5} execs/s + {:>5} minimizations/s : {}\n{}\n{}",
                    executions,
                    minimizations,
                    counts,
                    fuzzer,
                    corpus,
                );
                log::debug!("{:?}", fuzzer);
            } else {
                log::info!(
                    "{:>5} execs/s + {:>5} minimizations/s : {}\n{}",
                    executions,
                    minimizations,
                    counts,
                    corpus,
                );
            }

            // keep execution history
            if let Some(executions_history) = &mut self.executions_history {
                executions_history.push(history);
            }

            self.new_coverage = false;
            self.last_executions = self.executions;
            self.last_minimizations = self.minimizations;
            self.last_counts = self.counts.clone();
            self.last_update = Instant::now();
        }

        // early exit when disabled
        if !self.enabled {
            return Ok(());
        }

        if let Some(info) = info {
            // track input size over time
            let shorter_input = matches!(result, CorpusResultKind::ShorterInput);
            if new_coverage || shorter_input {
                if let Some(input_size_history) = &mut self.input_size_history {
                    input_size_history.push(InputSizeHistory {
                        timestamp: epoch()?,
                        input_id: info.input_id,
                        input_len: info.input_len,
                        input_bytes: info.input_bytes,
                    })
                }
            }

            // track fuzzer stats
            if let Some(fuzzer) = &mut self.fuzzer {
                fuzzer.process_result(info);
            }
        }

        Ok(())
    }

    pub fn process_minimization(&mut self) {
        self.minimizations += 1;
    }

    pub fn process_counts(&mut self, counts: EmulatorCounts) {
        self.counts += counts;
    }
}

impl CorpusStatistics {
    pub fn sort(&mut self) {
        self.inputs.sort_by_key(|input_stats| input_stats.id);
        self.features.sort_by_key(|(feature, _)| *feature);
        self.rare_features.sort();
    }
}

impl FuzzerStatistics {
    pub fn new(fuzzer_name: String) -> Self {
        Self {
            fuzzer_name,
            stop_reason: FxHashMap::default(),
        }
    }

    pub fn process_result<'a>(&mut self, info: StatisticsInfo) {
        // stop reason counts
        *self.stop_reason.entry(info.stop_reason).or_default() += 1;
    }
}
