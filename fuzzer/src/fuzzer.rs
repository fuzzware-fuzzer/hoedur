use std::{
    path::{Path, PathBuf},
    rc::Rc,
    sync::atomic::Ordering,
    vec,
};

use anyhow::{Context, Result};
use archive::{
    tar::{write_file, write_serialized},
    Archive, ArchiveBuilder,
};
use common::{
    config::{
        corpus::REPLACE_WITH_SHORTER_INPUT,
        fuzzer::{
            ARCHIVE_EARLY_WRITE, ARCHIVE_KEEP_SHORTER_INPUT, MINIMIZE_INPUT_LENGTH,
            MINIMIZE_MUTATION_CHAIN, MUTATION_COUNT_POW2, MUTATION_MODE_DISTRIBUTION,
            MUTATION_MODE_MONO, MUTATION_MODE_SWITCH_CHANCE, MUTATION_STACKING,
            MUTATOR_DISTRIBUTION, RANDOM_CHANCE_INPUT, RANDOM_NO_VIABLE_MUTATION,
            REMOVE_UNREAD_VALUES, SNAPSHPOT_MUTATION_LIMIT, STREAM_RANDOM_DISTRIBUTION,
        },
        mutation::MAX_RETRY,
        statistics::EXECUTIONS_HISTORY,
    },
    exit::{signal_exit_point, EXIT},
    fs::decoder,
    random::{DeriveRandomSeed, FastRand},
    time::epoch,
};
use emulator::{Emulator, EmulatorSnapshot, ExecutionResult, RunMode, StopReason};
use enum_index::IndexEnum;
use modeling::input::{stream::Stream, InputFile};
use rand_distr::{Distribution, WeightedAliasIndex};

use crate::{
    corpus::{Corpus, CorpusResult, CorpusResultKind, InputInfo, InputResult, NewCoverage},
    corpus_archive::{write_input_file, IntoInputFileIter},
    dict::Dictionary,
    mutation::{Mutation, MutationContext, MutationLog, MutationMode, MutatorKind, Random},
    statistics::{Statistics, StatisticsInfo},
    stream::{ChronoStream, StreamIndex},
    stream_distribution::{StreamDistribution, StreamRandomDistribution},
};

pub struct Fuzzer {
    archive: ArchiveBuilder,
    emulator: Emulator<InputFile>,
    pre_fuzzing: EmulatorSnapshot,
    corpus: Corpus,
    statistics: Statistics,
    dictionary: Dictionary,
    snapshots: bool,

    seed: u64,

    distribution_mutator: WeightedAliasIndex<usize>,
    distribution_mutation_mode: WeightedAliasIndex<usize>,
    distribution_stream_select: WeightedAliasIndex<usize>,

    mutation_log: Vec<Rc<MutationLog>>,
    random: Option<Random>,
}

#[derive(Debug, Clone)]
pub enum InputFork {
    BaseFork {
        input: InputFile,
        chrono_stream: Rc<ChronoStream>,
    },
    ExecutedFork {
        result: InputResult,
        stream_distribution: Box<StreamDistribution>,
    },
}

impl InputFork {
    pub fn from_base(input: InputFile, chrono_stream: Rc<ChronoStream>) -> Self {
        InputFork::BaseFork {
            input,
            chrono_stream,
        }
    }

    pub fn from_result(result: InputResult) -> Self {
        InputFork::ExecutedFork {
            result,
            stream_distribution: Box::default(),
        }
    }

    pub fn into_inner(self) -> InputFile {
        match self {
            InputFork::BaseFork { input, .. } => input,
            InputFork::ExecutedFork { result, .. } => result.into_inner(),
        }
    }

    pub fn inner_ref(&self) -> (&InputFile, &ChronoStream) {
        match self {
            InputFork::BaseFork {
                input,
                chrono_stream,
            } => (input, chrono_stream),
            InputFork::ExecutedFork { result, .. } => (result.file(), result.chrono_stream()),
        }
    }

    pub fn inner_ref_mut(&mut self) -> (&mut InputFile, &ChronoStream) {
        match self {
            InputFork::BaseFork {
                ref mut input,
                chrono_stream,
            } => (input, chrono_stream),
            InputFork::ExecutedFork { result, .. } => result.inner_ref_mut(),
        }
    }

    pub fn file(&self) -> &InputFile {
        match self {
            InputFork::BaseFork { input, .. } => input,
            InputFork::ExecutedFork { result, .. } => result.file(),
        }
    }

    pub fn file_mut(&mut self) -> &mut InputFile {
        match self {
            InputFork::BaseFork { input, .. } => input,
            InputFork::ExecutedFork { result, .. } => result.file_mut(),
        }
    }

    pub fn chrono_stream(&self) -> &ChronoStream {
        match self {
            InputFork::BaseFork { chrono_stream, .. } => chrono_stream,
            InputFork::ExecutedFork { result, .. } => result.chrono_stream(),
        }
    }
}

impl Fuzzer {
    pub fn new(
        name: String,
        seed: Option<u64>,
        import_corpus: Vec<PathBuf>,
        statistics: bool,
        snapshots: bool,
        archive: ArchiveBuilder,
        mut emulator: Emulator<InputFile>,
    ) -> Result<Self> {
        // pre-fuzzer snapshot
        let pre_fuzzing = emulator
            .snapshot_create()
            .context("Failed to create pre-fuzzer snapshot")?;

        // set seed
        let seed = seed.unwrap_or_else(|| {
            // "random" seed (based on time + thread id)
            fastrand::u64(..)
        });
        fastrand::seed(seed);
        log::debug!("initial random seed = {:#x?}", seed);

        // collect dictionary
        let mut dictionary = Dictionary::default();
        for memory_block in emulator.memory_blocks().filter(|mem| mem.readonly) {
            dictionary.scan_memory_block(memory_block.data);
        }

        // create fuzzer
        let mut fuzzer = Self {
            archive,
            emulator,
            pre_fuzzing,
            corpus: Corpus::new(),
            statistics: Statistics::new(name, statistics),
            dictionary,
            snapshots,
            seed,
            distribution_mutator: WeightedAliasIndex::new(MUTATOR_DISTRIBUTION.to_vec())
                .context("Failed to create a weighted mutator distribution.")?,
            distribution_mutation_mode: WeightedAliasIndex::new(
                MUTATION_MODE_DISTRIBUTION.to_vec(),
            )
            .context("Failed to create a weighted mutation mode distribution.")?,
            distribution_stream_select: WeightedAliasIndex::new(
                STREAM_RANDOM_DISTRIBUTION.to_vec(),
            )
            .context("Failed to create a weighted stream select distribution.")?,
            mutation_log: vec![],
            random: None,
        };

        // verify config distribution count matches enum len
        assert_eq!(MUTATOR_DISTRIBUTION.len(), MutatorKind::VARIANT_COUNT);
        assert_eq!(
            MUTATION_MODE_DISTRIBUTION.len(),
            MutationMode::VARIANT_COUNT
        );
        assert_eq!(
            STREAM_RANDOM_DISTRIBUTION.len(),
            StreamRandomDistribution::VARIANT_COUNT
        );

        // write fuzzer config to corpus
        fuzzer.write_config()?;

        // load and run input files from old corpus
        if !import_corpus.is_empty() {
            log::info!("Re-run existing corpus ...");
            for corpus in import_corpus {
                if let Err(err) = fuzzer.load_corpus(&corpus) {
                    log::error!("Failed to load corpus: {:?}", err);
                }
            }
        }

        // add empty input if corpus is empty
        if fuzzer.corpus.is_empty() {
            fuzzer.run_fuzzer_input(InputFile::default(), &fuzzer.pre_fuzzing.clone(), false)?;
        }

        Ok(fuzzer)
    }

    fn load_corpus(&mut self, corpus: &Path) -> Result<()> {
        // load input files
        log::info!("Loading corpus archive {:?} ...", corpus);
        let mut corpus_archive = Archive::from_reader(decoder(corpus)?);

        // run inputs
        for result in corpus_archive.iter()?.input_files() {
            signal_exit_point()?;

            // get next input file
            let entry = match result {
                Ok(input) => input,
                Err(err) => {
                    log::error!("Failed to parse entry: {:?}", err);
                    continue;
                }
            };

            // original input id
            let mut input = entry.input;
            let id = input.id();

            // set new input id
            input.replace_id(&InputFile::default());

            // run input
            log::info!("Running input {} ...", id);
            self.run_fuzzer_input(input, &self.pre_fuzzing.clone(), true)?;
        }

        Ok(())
    }

    pub fn run(&mut self) -> Result<()> {
        if self.snapshots {
            self.run_snapshot_fuzzer()?;
        } else {
            self.run_plain_fuzzer()?;
        }

        if !ARCHIVE_EARLY_WRITE {
            self.write_input_files()?;
        }

        self.write_statistics()
    }

    fn run_plain_fuzzer(&mut self) -> Result<()> {
        log::info!("Started plain fuzzing...");
        while !EXIT.load(Ordering::Relaxed) {
            // random input for mutation
            let input = self
                .next_input()
                .context("Failed to get random input.")?
                .fork();

            self.run_mutations(input, None, &self.pre_fuzzing.clone())?;
        }

        Ok(())
    }

    fn run_snapshot_fuzzer(&mut self) -> Result<()> {
        if MINIMIZE_MUTATION_CHAIN {
            // TODO: add support:
            // - pass base_input into minimize_mutation_chain
            // - set cursor when base_input is some
            anyhow::bail!("Snapshot fuzzer doesn't support MINIMIZE_MUTATION_CHAIN");
        }

        log::info!("Started snapshot fuzzing...");
        while !EXIT.load(Ordering::Relaxed) {
            // get random base input
            let base_info = self.next_input().context("Failed to get random input.")?;
            let mut base_input = base_info.result().file().clone();
            base_input.set_read_limit(fastrand::usize(0..=base_input.len()));

            // emulator counts before execution
            let counts = EXECUTIONS_HISTORY.then(|| self.emulator.counts());

            // run base input
            let base_result = self
                .emulator
                .run(base_input, RunMode::Normal)
                .context("run emulator")?;

            // track emulator counts
            if let Some(base) = counts {
                self.statistics
                    .process_counts(base_result.counts.clone() - base);
            }

            // base input
            let base_input = InputResult::from(base_result).as_fork();
            log::trace!("base_input: {}", base_input.file());

            // emulator snapshot (between input parts)
            let snapshot = self
                .emulator
                .snapshot_create()
                .context("Failed to create emulator snapshpot")?;

            for _ in 0..SNAPSHPOT_MUTATION_LIMIT {
                if self.run_mutations(base_input.clone(), Some(base_input.file()), &snapshot)? {
                    break;
                }
            }

            // restore emulator
            self.emulator.snapshot_restore(&self.pre_fuzzing);
        }

        Ok(())
    }

    fn run_mutations(
        &mut self,
        mut input: InputFork,
        base_input: Option<&InputFile>,
        snapshot: &EmulatorSnapshot,
    ) -> Result<bool> {
        log::debug!(
            "mutate new input forked from base input {:?}",
            input.file().parent()
        );

        let mutation_stack = 1 << fastrand::usize(MUTATION_COUNT_POW2);

        // random seed based on fuzzer seed and input id
        let random_seed = self.seed.derive(&input.file().id());
        input.file_mut().set_random_seed(random_seed);

        for i in 0..mutation_stack {
            let mut last_mutation = (i + 1) == mutation_stack;

            // add one input mutation
            let mutated = self.mutate(&mut input).context("mutate input file")?;

            // add random mutation after last mutation with 1/4 chance or when no viable mutation was found
            let force_random = RANDOM_NO_VIABLE_MUTATION && !mutated;
            let input_random = last_mutation
                && RANDOM_CHANCE_INPUT
                    .map(|chance| fastrand::u8(0..chance) == 0)
                    .unwrap_or(false);
            let random = if force_random || input_random {
                last_mutation = true;
                self.add_random_count(&mut input)
            } else {
                false
            };

            // skip execution if neither successful mutated nor random count added
            if !mutated && !random {
                break;
            }

            // execute input:
            // - !MUTATION_STACKING: after each mutation (libfuzzer like)
            // - MUTATION_STACKING: after last mutation (afl like)
            if !MUTATION_STACKING || last_mutation {
                if let Some(result) = self.run_fuzzer_input(input.into_inner(), snapshot, false)? {
                    // no new coverage found => continue mutating input
                    input = result.as_fork();

                    // set/reset cursor
                    match base_input {
                        Some(base) => input.file_mut().set_cursor(base),
                        None => input.file_mut().reset_cursor(),
                    }
                } else {
                    // new coverage found => input was added to corpus
                    // or emulator exit
                    return Ok(true);
                }
            }

            // make sure we exit after last viable mutation was run
            // this can be early when only the random mutation was viable (empty input)
            if last_mutation {
                break;
            }
        }

        Ok(false)
    }

    fn run_fuzzer_input(
        &mut self,
        input: InputFile,
        snapshot: &EmulatorSnapshot,
        import: bool,
    ) -> Result<Option<InputResult>> {
        // emulator counts before execution
        let counts = EXECUTIONS_HISTORY.then(|| self.emulator.counts());

        // run input
        let result = self
            .emulator
            .run(input, RunMode::Leaf)
            .context("run emulator")?;

        if import {
            log::info!("Result: {}", result);
        }

        if result.stop_reason == StopReason::UserExitRequest {
            return Ok(None);
        }

        // track emulator counts
        if let Some(base) = counts {
            self.statistics.process_counts(result.counts.clone() - base);
        }

        // process results
        let result = self
            .process_result(result, import)
            .context("Process execution result")?;

        // restore emulator
        self.emulator.snapshot_restore(snapshot);

        Ok(result)
    }

    fn run_minimized_input(&mut self, input: InputFile) -> Result<CorpusResult> {
        // restore emulator
        self.emulator.snapshot_restore(&self.pre_fuzzing);

        // emulator counts before execution
        let counts = EXECUTIONS_HISTORY.then(|| self.emulator.counts());

        // run input
        let result = self
            .emulator
            .run(input, RunMode::Leaf)
            .context("run emulator")?;

        // track emulator counts
        if let Some(base) = counts {
            self.statistics.process_counts(result.counts.clone() - base);
        }

        // process results
        let input_result = InputResult::new(
            result.hardware.input,
            epoch()?,
            result.counts.basic_block(),
            result.stop_reason,
            result.hardware.access_log,
        );

        self.statistics.process_minimization();
        self.corpus.process_result(
            input_result,
            self.emulator.get_coverage_bitmap(),
            self.mutation_log
                .iter()
                .map(|log| &log.mutation.target().context),
            false,
        )
    }

    pub fn next_input(&mut self) -> Result<&InputInfo> {
        self.mutation_log.clear();
        self.random = None;
        self.corpus.random_input()
    }

    pub fn mutate(&mut self, input: &mut InputFork) -> Result<bool> {
        // can't mutate empty input with no streams
        if input.file().input_streams().is_empty() {
            return Ok(false);
        }

        // next mutation context (stream / mono)
        let mutation_context = if MUTATION_MODE_MONO {
            self.next_mutation_context()
        } else {
            MutationContext::Stream(self.next_stream_random_distribution())
        };

        // mutate input stream
        if let Some(mutation) = self.mutate_stream(input, mutation_context)? {
            self.mutation_log.push(Rc::new(mutation));
            return Ok(true);
        }

        log::debug!(
            "no viable mutation was found for input {} (parent {:?}), this should happen very rarely",
            input.file().id(),
            input.file().parent()
        );
        Ok(false)
    }

    fn next_mutation_context(&mut self) -> MutationContext {
        // mutations depending on last stream mutation target
        let last_target = self
            .mutation_log
            .last()
            .map(|log| (&log.mode, log.mutation.target()));

        match last_target {
            Some((old_mode, last_target)) => {
                // switch mode with a 1/8 chance
                let new_mode = if fastrand::u8(0..MUTATION_MODE_SWITCH_CHANCE) == 0 {
                    MutationMode::index_enum(self.distribution_mutation_mode.sample(&mut FastRand))
                        .expect("MutationMode index is valid")
                } else {
                    *old_mode
                };

                match new_mode {
                    MutationMode::Stream => {
                        MutationContext::Stream(self.next_stream_random_distribution())
                    }
                    MutationMode::Mono => MutationContext::Mono {
                        context: last_target.context.clone(),
                    },
                }
            }
            // no previous target => fallback to stream
            None => MutationContext::Stream(self.next_stream_random_distribution()),
        }
    }

    fn add_random_count(&mut self, input: &mut InputFork) -> bool {
        let random = Random::new();

        if random.is_valid_and_effective(input.file()) {
            random.mutate(input.file_mut());
            self.random = Some(random);
            true
        } else {
            false
        }
    }

    fn mutate_stream(
        &mut self,
        input: &mut InputFork,
        context: MutationContext,
    ) -> Result<Option<MutationLog>> {
        for _ in 0..MAX_RETRY {
            if let Some(target) = self.mutation_target(input, &context)? {
                if let Some(mutation) = self.random_mutation(input, target)? {
                    let effective = mutation.apply(input)?;

                    if effective {
                        return Ok(Some(MutationLog {
                            mode: MutationMode::from(&context),
                            mutation,
                            distribution: context.distribution(),
                        }));
                    }
                }
            }
        }

        Ok(None)
    }

    fn mutation_target(
        &mut self,
        input: &mut InputFork,
        context: &MutationContext,
    ) -> Result<Option<StreamIndex>> {
        let context = match context {
            MutationContext::Stream(distribution) => match input {
                InputFork::BaseFork { input, .. } => input
                    .parent()
                    .and_then(|parent| self.corpus.random_stream_index(parent, *distribution))
                    .context("InputFork missing parent stream distribution")?,
                InputFork::ExecutedFork {
                    result,
                    stream_distribution,
                } => {
                    let info = result
                        .file()
                        .parent()
                        .and_then(|parent| self.corpus.input(parent))
                        .context("InputFork missing parent")?;

                    stream_distribution
                        .random_stream_index(info.stream_info(), result, *distribution)
                        .context("Random stream index pick failed for executed fork input")
                }
            }
            .context("Failed to pick random input stream")?
            .clone(),
            MutationContext::Mono { context } => context.clone(),
        };

        let is = input
            .file()
            .input_streams()
            .get(&context)
            .context("Failed to get input stream.")?;

        Ok(Some(StreamIndex {
            context,
            index: if is.len() > is.cursor() {
                fastrand::usize(is.cursor()..is.len())
            } else {
                is.cursor()
            },
        }))
    }

    fn random_mutation(&self, input: &InputFork, target: StreamIndex) -> Result<Option<Mutation>> {
        let mutator = self.next_mutator();
        Mutation::create(mutator, target, input, &self.dictionary, || {
            self.corpus.random_input().map(|info| info.result()).ok()
        })
        .with_context(|| format!("Failed to create {mutator:?} mutator"))
    }

    fn process_result(
        &mut self,
        result: ExecutionResult<InputFile>,
        import: bool,
    ) -> Result<Option<InputResult>> {
        let input = &result.hardware.input;
        let mut statistics_info = self.statistics.enabled().then(|| {
            StatisticsInfo::from_input(input, result.stop_reason.clone(), self.mutation_log.len())
        });

        let corpus_result = self.corpus.process_result(
            InputResult::new(
                result.hardware.input,
                epoch()?,
                result.counts.basic_block(),
                result.stop_reason,
                result.hardware.access_log,
            ),
            self.emulator.get_coverage_bitmap(),
            self.mutation_log
                .iter()
                .map(|log| &log.mutation.target().context),
            true,
        )?;
        let corpus_result_kind = CorpusResultKind::from(&corpus_result);
        let input_result = match corpus_result {
            CorpusResult::NewCoverage(mut info) => {
                // remove uneffective mutations
                // skip mutation chain minimizations for imported inputs
                if !import && MINIMIZE_MUTATION_CHAIN {
                    info = self
                        .minimize_mutation_chain(info)
                        .context("minimize mutations")?;
                }

                // trim end of input file (binary search for uneffective input values)
                if MINIMIZE_INPUT_LENGTH {
                    let read_limit = self
                        .minimize_input_length(&info)
                        .context("minimize input length")?;

                    if let Some(statistics_info) = &mut statistics_info {
                        statistics_info.read_limit = read_limit;
                    }
                }

                // trim end of input file (unread input values)
                if REMOVE_UNREAD_VALUES {
                    info.result_mut().file_mut().remove_unread_values();
                }

                // remove empty input streams
                info.result_mut().file_mut().remove_empty_streams();

                // update statistics info
                if let Some(statistics_info) = &mut statistics_info {
                    statistics_info.update_input(info.result());
                }

                // write to corpus archive
                if ARCHIVE_EARLY_WRITE || !info.result().category().schedule() {
                    write_input_file(&mut self.archive.borrow_mut(), info.result())?;
                }

                // add to corpus
                self.corpus
                    .add_result(info)
                    .context("Add result to corpus")?;
                None
            }
            CorpusResult::ShorterInput(result) => {
                let result = self.shorter_input(result)?;

                // update statistics info
                if let Some(statistics_info) = &mut statistics_info {
                    statistics_info.input_id =
                        result.file().parent().context("missing parent input id")?;
                    statistics_info.update_input(&result);
                }

                Some(result)
            }
            CorpusResult::Uninteresting(result) => Some(result),
        };

        if !import {
            self.corpus.update()?;
        }
        self.statistics
            .process_result(statistics_info, corpus_result_kind, &self.corpus)?;

        Ok(input_result)
    }

    fn shorter_input(&mut self, mut result: InputResult) -> Result<InputResult> {
        if REMOVE_UNREAD_VALUES {
            result.file_mut().remove_unread_values();
        }

        result.file_mut().remove_empty_streams();

        // replace shorter input
        if REPLACE_WITH_SHORTER_INPUT {
            // write to corpus archive
            if ARCHIVE_KEEP_SHORTER_INPUT {
                write_input_file(&mut self.archive.borrow_mut(), &result)?;
            }

            // update corpus file
            self.corpus
                .replace_input(result.clone())
                .context("Replace with shorter input")?;
        }

        Ok(result)
    }

    fn minimize_mutation_chain(&mut self, info: NewCoverage) -> Result<NewCoverage> {
        // can't minimize with only one mutation
        if self.mutation_log.len() <= 1 {
            return Ok(info);
        }

        // get base input (input without mutations)
        let new_input = info.result().file().clone();
        let parent_input = match new_input.parent() {
            Some(parent_id) => self
                .corpus
                .input(parent_id)
                .context("Missing parent input in corpus")?,

            // can't minimize without base input
            None => return Ok(info),
        };
        let random_seed = self.seed.derive(&new_input.id());
        let mut base_input = parent_input.fork();
        base_input.file_mut().reset_cursor(); // TODO: set base_input cursor
        base_input.file_mut().replace_id(&new_input);
        base_input.file_mut().set_random_seed(random_seed);

        // keep complete input info in case no minimize is possible
        let mut minimized = info;

        // mutations
        let random_mutation = usize::from(self.random.is_some());
        let mut mutation_log = self.mutation_log.clone();
        let mut idx = mutation_log.len() - 1 + random_mutation;

        // keep removing unneeded mutations
        loop {
            let mut input = base_input.clone();
            let mut removed = vec![];
            let mut removed_random = false;

            // apply all mutations except one
            for (i, log) in mutation_log.iter().enumerate() {
                // skip mutation at idx
                if i == idx {
                    removed.push(i);
                    continue;
                }

                // apply mutation
                if !log.mutation.apply(&mut input)? {
                    // remove invalid / uneffective mutations
                    removed.push(i);
                }
            }

            // treat random mutation as last mutation (if any)
            match &self.random {
                Some(random) if idx == mutation_log.len() => {
                    // apply random mutation
                    random.mutate(input.file_mut());
                    removed_random = true;
                }
                _ => {}
            }

            // run input
            match self.run_minimized_input(input.into_inner())? {
                CorpusResult::NewCoverage(info) => {
                    if verify_minimization(&info, &minimized) {
                        // remove mutations in reverse order (so index is valid)
                        for index in removed.into_iter().rev() {
                            log::debug!("found unneeded mutation: {:x?}", mutation_log[index]);
                            mutation_log.remove(index);
                        }

                        // remove random
                        if removed_random {
                            self.random = None;
                        }

                        // update minimal input info
                        minimized = info;
                    }
                }
                CorpusResult::ShorterInput(result) => {
                    let _ = self.shorter_input(result)?;
                }
                CorpusResult::Uninteresting(_) => {}
            }

            if idx > 0 {
                // next mutation
                idx -= 1;
            } else {
                // last mutation => stop
                break;
            }
        }

        // update mutation logs
        self.mutation_log = mutation_log;

        Ok(minimized)
    }

    fn minimize_input_length(&mut self, info: &NewCoverage) -> Result<Option<usize>> {
        // minimize input length
        let mut input = info.result().file().clone();
        let mut left = 0;
        let mut right = input.len();
        while left < right {
            let read_limit = left + (right - left) / 2;

            input.reset_cursor();
            input.set_read_limit(read_limit);
            input = match self.run_minimized_input(input)? {
                CorpusResult::NewCoverage(minimized) => {
                    if verify_minimization(info, &minimized) {
                        log::trace!("found shorter input with read_limit = {}", read_limit);

                        // update right bound
                        input = minimized.result().clone().into_inner();
                        right = read_limit;

                        continue;
                    } else {
                        minimized.into_inner()
                    }
                }
                CorpusResult::ShorterInput(result) => self.shorter_input(result.clone())?,
                CorpusResult::Uninteresting(result) => result,
            }
            .into_inner();

            // update left bound
            left = read_limit + 1;
        }
        debug_assert_eq!(left, right);

        let read_limit = if right < input.len() {
            log::debug!("found shortest input with read_limit = {}", right);
            Some(right)
        } else {
            None
        };

        Ok(read_limit)
    }

    fn write_config(&mut self) -> Result<()> {
        let timestamp = epoch()?;

        // write seed
        write_file(
            &mut self.archive.borrow_mut(),
            "config/seed.bin",
            timestamp,
            &self.seed.to_be_bytes(),
        )
        .context("write corpus seed")?;

        Ok(())
    }

    fn write_statistics(&mut self) -> Result<()> {
        let timestamp = epoch()?;

        // executions history
        if let Some(executions) = self.statistics.executions() {
            write_serialized(
                &mut self.archive.borrow_mut(),
                "statistics/executions.bin",
                timestamp,
                &executions,
            )
            .context("write executions history")?;
        }

        // input size history
        if let Some(input_size) = self.statistics.input_size() {
            write_serialized(
                &mut self.archive.borrow_mut(),
                "statistics/input-size.bin",
                timestamp,
                &input_size,
            )
            .context("write input size history")?;
        }

        Ok(())
    }

    fn write_input_files(&mut self) -> Result<()> {
        for info in self.corpus.inputs() {
            write_input_file(&mut self.archive.borrow_mut(), info.result())?;
        }

        Ok(())
    }

    fn next_mutator(&self) -> MutatorKind {
        MutatorKind::index_enum(self.distribution_mutator.sample(&mut FastRand))
            .expect("Mutator index is valid")
    }

    fn next_stream_random_distribution(&self) -> StreamRandomDistribution {
        StreamRandomDistribution::index_enum(self.distribution_stream_select.sample(&mut FastRand))
            .expect("StreamRandomDistribution index is valid")
    }
}

/// verify stop reason and unqiue features are equal
fn verify_minimization(new: &NewCoverage, old: &NewCoverage) -> bool {
    new.result().stop_reason() == old.result().stop_reason()
        && new.uniq_features().is_superset(old.uniq_features())
}
