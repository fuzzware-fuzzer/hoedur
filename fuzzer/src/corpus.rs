use std::{fmt, hash::Hash, iter, rc::Rc, str::FromStr};

use anyhow::{Context, Result};
use common::{
    config::{
        corpus::*,
        fuzzer::{
            STREAM_DISTRIBUTION_SUCCESS, SUCCESS_DISTRIBUTION_PARENT_SUCCESS_NEW_COVERAGE,
            SUCCESS_DISTRIBUTION_PARENT_SUCCESS_SHORTER_INPUT, SUCCESS_DISTRIBUTION_RESET_INTERVAL,
            SUCCESS_DISTRIBUTION_UPDATE_INTERVAL,
        },
    },
    hashbrown::hash_map::Entry,
    random::FastRand,
    time::{epoch, Epoch},
    FxHashMap, FxHashSet,
};
use emulator::{coverage::RawBitmap, ExecutionResult, StopReason};
use enum_index::EnumIndex;
use enum_index_derive::EnumIndex;
use enum_kinds::EnumKind;
use lazy_init::LazyTransform;
use modeling::input::{stream::Stream, InputContext, InputFile, InputId};
use rand::{
    distributions::{WeightedError, WeightedIndex},
    prelude::*,
};
use serde::{Deserialize, Serialize};
use variant_count::VariantCount;

use crate::{
    coverage::{edge_bitmap, Edge, Feature},
    fuzzer::InputFork,
    statistics::{CorpusStatistics, InputStatistics, SuccessRate},
    stream::ChronoStream,
    stream_distribution::{StreamDistribution, StreamRandomDistribution},
};
#[derive(Debug)]
pub struct Corpus {
    inputs: FxHashMap<InputId, InputInfo>,
    input_id: Vec<InputId>,
    input_weighted_index: Option<WeightedIndex<f64>>,
    feature_frequency: FxHashMap<Feature, u16>,
    rare_features: FxHashSet<Feature>,
    edges: FxHashSet<Edge>,
    unscheduled_features: FxHashSet<Feature>,
    most_abundant_rare_feature_frequency: u16,
    mutation_count: usize,
}

impl fmt::Display for Corpus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Corpus has {:>6} {:<10} ({:>3} rare features, {:>3} unscheduled features, most abundant feature frequency: {:>5})",
            self.feature_frequency.len(),
            "features",
            self.rare_features.len(),
            self.unscheduled_features.len(),
            self.most_abundant_rare_feature_frequency
        )?;
        writeln!(f, "{:>17} {:<10}", self.edges.len(), "edges")?;
        writeln!(f, "{:>17} {:<10}", self.inputs.len(), "inputs")?;
        write!(f, "{:>17} {:<10}", self.mutation_count, "executions")
    }
}

impl Default for Corpus {
    fn default() -> Self {
        Self::new()
    }
}

impl Corpus {
    pub fn new() -> Self {
        Self {
            inputs: FxHashMap::default(),
            input_id: vec![],
            input_weighted_index: None,
            feature_frequency: FxHashMap::default(),
            rare_features: FxHashSet::default(),
            edges: FxHashSet::default(),
            unscheduled_features: FxHashSet::default(),
            most_abundant_rare_feature_frequency: 1,
            mutation_count: 0,
        }
    }

    pub fn process_result<'a>(
        &mut self,
        result: InputResult,
        raw_bitmap: &RawBitmap,
        mutation_log: impl Iterator<Item = &'a InputContext>,
        update: bool,
    ) -> Result<CorpusResult> {
        // find base input (parent)
        let mut base_input = match result.input.parent() {
            Some(id) => self.inputs.get_mut(&id),
            None => None,
        };

        // process result (updates local and global feature frequencies)
        let mut uniq_features = FxHashSet::default();
        let mut base_input_uniq_features = 0;

        // collect feature bitmap
        // NOTE: we implictly assume that the bitmap was not changed for the given result
        let bitmap = edge_bitmap(raw_bitmap);

        // process all features of this input, collect uniq_features (if scheduled input)
        let schedule = result.category().schedule();
        for feature in bitmap.features().iter().copied() {
            match self.feature_frequency.entry(feature) {
                Entry::Occupied(mut entry) if update => {
                    let frequency = entry.get_mut();
                    let new_frequency = frequency.saturating_add(1);

                    // keep track of most_abundant_rare_feature_frequency
                    if *frequency == self.most_abundant_rare_feature_frequency
                        && self.rare_features.contains(&feature)
                    {
                        self.most_abundant_rare_feature_frequency = new_frequency;
                    }

                    // increment existing feature frequency
                    *frequency = new_frequency;

                    // update base input rare feature frequency (or add a new feature)
                    if let Some(ref mut base) = base_input {
                        if self.rare_features.contains(&feature) {
                            base.update_feature_frequency(feature);
                        }
                    }
                }
                Entry::Vacant(_) if schedule => {
                    // new unique feature found
                    uniq_features.insert(feature);
                }
                _ => {}
            }

            // check if new input is a superset of base input
            if let Some(ref base) = base_input {
                if base.uniq_features.contains(&feature) {
                    base_input_uniq_features += 1;
                }
            }
        }

        // collect uniq_features for unscheduled input
        if !schedule {
            let unscheduled_features = &self.unscheduled_features;
            uniq_features = bitmap
                .features()
                .iter()
                .copied()
                .filter(|feature| !unscheduled_features.contains(feature))
                .collect();
        }

        // input contains rare features => keep
        let result_kind = if !uniq_features.is_empty() {
            CorpusResultKind::NewCoverage
        } else {
            match &base_input {
                // smaller input with same unqiue features found
                Some(base)
                    if base_input_uniq_features == base.uniq_features.len()
                        && result.read_count() < base.result.read_count()
                        && result.stop_reason() == base.result.stop_reason() =>
                {
                    CorpusResultKind::ShorterInput
                }
                _ => CorpusResultKind::Uninteresting,
            }
        };

        if update {
            // update mutation count
            self.mutation_count += 1;

            // update base input
            if let Some(ref mut base_input) = base_input {
                base_input.mutation_count += 1;
                base_input.child_results[result.category().enum_index()] += 1;
                base_input.request_energy_update();

                // update stream info
                if (SUCCESS_DISTRIBUTION_PARENT_SUCCESS_NEW_COVERAGE
                    && matches!(result_kind, CorpusResultKind::NewCoverage))
                    || (SUCCESS_DISTRIBUTION_PARENT_SUCCESS_SHORTER_INPUT
                        && matches!(result_kind, CorpusResultKind::ShorterInput))
                {
                    base_input.stream_info.add_success(mutation_log);
                } else {
                    base_input.stream_info.add_count(mutation_log);
                }

                // update stream success distribution
                if base_input.mutation_count % SUCCESS_DISTRIBUTION_UPDATE_INTERVAL == 0 {
                    base_input.stream_distribution.request_success_update();
                }

                // reset stream success distribution
                if let Some(reset_interval) = SUCCESS_DISTRIBUTION_RESET_INTERVAL {
                    if base_input.mutation_count % reset_interval == 0 {
                        base_input.stream_info.reset_success();
                    }
                }
            }
        }

        Ok(match result_kind {
            CorpusResultKind::NewCoverage => {
                CorpusResult::NewCoverage(NewCoverage::new(result, uniq_features))
            }
            CorpusResultKind::ShorterInput => CorpusResult::ShorterInput(result),
            CorpusResultKind::Uninteresting => CorpusResult::Uninteresting(result),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.inputs.is_empty()
    }

    pub fn update(&mut self) -> Result<()> {
        self.update_rare_features();

        // update all input weights when needed or every 128 executions
        if self.input_weighted_index.is_none()
            || (self.mutation_count % UPDATE_ENERGY_INTERVAL) == 0
        {
            self.update_input_weights()
                .context("Failed to update input weights")?;
        }

        Ok(())
    }

    fn update_rare_features(&mut self) {
        // remove abundant rare features
        while self.rare_features.len() > MIN_RARE_FEATURES
            && self.most_abundant_rare_feature_frequency > FEATURE_FREQUENCY_THRESHOLD
        {
            // current most_abundant_rare_feature
            let (feature, frequency) = self.most_abundant_rare_feature();
            log::trace!(
                "removing most abundant rare feature = {:x?}: {}",
                feature,
                frequency
            );
            debug_assert_eq!(frequency, self.most_abundant_rare_feature_frequency);

            // remove most abundant rare feature
            self.rare_features.remove(&feature);

            // remove frequency in inputs
            for input_info in self.inputs.values_mut() {
                input_info.remove_feature_frequency(feature);
            }

            // set next most_abundant_rare_feature_frequency
            self.most_abundant_rare_feature_frequency = self.most_abundant_rare_feature().1;
        }
    }

    pub fn add_result(&mut self, new_coverage: NewCoverage) -> Result<()> {
        log::debug!("add new input {}", new_coverage.result.file().id());

        self.update_rare_features();
        let rare_features = self.rare_features.len();
        let base_input = new_coverage
            .result
            .file()
            .parent()
            .and_then(|parent_id| self.inputs.get_mut(&parent_id));
        let info = InputInfo::new(
            rare_features,
            new_coverage.uniq_features,
            base_input,
            new_coverage.result,
        )?;

        // update corpus unique features
        self.add_unique_features(&info);

        // add scheduled inputs to corpus
        if info.result.category().schedule() {
            // add input
            let id = info.result.input.id();
            let old = self.inputs.insert(id, info);
            self.input_id.push(id);

            debug_assert!(old.is_none());

            self.update_input_weights()?;
        }

        Ok(())
    }

    pub fn replace_input(&mut self, result: InputResult) -> Result<()> {
        // get parent input
        let inputs = &mut self.inputs;
        let parent = result
            .input
            .parent()
            .and_then(|id| inputs.get_mut(&id))
            .expect("Parent input file exists");
        log::debug!(
            "shorter input {} found replacing input {}",
            result.file().id(),
            parent.result.file().id(),
        );
        debug_assert!(result.read_count() < parent.result.read_count());

        // reset stream distribution
        parent.stream_distribution = StreamDistribution::default();

        // update stream info
        // NOTE: shorter inputs can have new input streams
        for context in result.file().input_streams().keys() {
            parent
                .stream_info
                .success
                .entry(context.clone())
                .or_insert(SuccessRate {
                    count: 1,
                    success: 1,
                });
        }

        // update input result
        parent.result.replace_with(result);

        Ok(())
    }

    fn most_abundant_rare_feature(&mut self) -> (Feature, u16) {
        self.rare_features
            .iter()
            .map(|feature| (*feature, *self.feature_frequency.get(feature).unwrap()))
            .max_by_key(|(_, frequency)| *frequency)
            .unwrap()
    }

    fn add_unique_features(&mut self, info: &InputInfo) {
        for feature in &info.uniq_features {
            if info.result.category().schedule() {
                log::trace!("new rare feature found: {:x?}", feature);

                // add edge
                self.edges.insert(feature.edge());

                // add global (rare) features
                let old_frequency = self.feature_frequency.insert(*feature, 1);
                let new = self.rare_features.insert(*feature);
                debug_assert!(new && old_frequency.is_none());

                // update input energy
                for input in self.inputs.values_mut() {
                    input.new_rare_feature();
                }
            } else {
                log::trace!("new unscheduled feature found: {:x?}", feature);

                // add global unscheduled features
                self.unscheduled_features.insert(*feature);
            }
        }
    }

    fn update_input_weights(&mut self) -> Result<()> {
        let count = self.scheduled_inputs().count();

        // check if corpus has scheduled inputs for distribution
        if count == 0 {
            self.input_weighted_index = None;
            anyhow::bail!("There are no scheduled inputs in corpus");
        }

        // calculate avg values
        let count = count as f64;
        let average_mutation_count = self
            .scheduled_inputs()
            .map(|input| input.mutation_count)
            .sum::<usize>() as f64
            / count;
        let average_basic_blocks = if SCALE_ENERGY {
            self.scheduled_inputs()
                .map(|input| input.result.basic_blocks)
                .sum::<usize>() as f64
                / count
        } else {
            1.
        };

        log::trace!("avg. mutations = {:?}", average_mutation_count);
        log::trace!("avg. basic blocks = {:?}", average_basic_blocks);
        log::trace!("global rare features = {:x?}", self.rare_features);

        // update weights
        let global_rare_feature_count = self.rare_features.len();
        let inputs = &mut self.inputs;
        let weights = self.input_id.iter().map(|id| {
            inputs.get_mut(id).unwrap().energy(
                global_rare_feature_count,
                average_basic_blocks,
                average_mutation_count,
            )
        });

        // create a WeightedIndex
        let weighted_index = WeightedIndex::new(weights)
            .or_else(|e| match e {
                WeightedError::AllWeightsZero => {
                    // fallback to uniform distribution
                    WeightedIndex::new(iter::repeat(1.).take(self.inputs.len()))
                }
                _ => Err(e),
            })
            .context("Failed to create a weighted index distribution.")?;

        // update weighted_index cache
        self.input_weighted_index = Some(weighted_index);

        Ok(())
    }

    fn random_input_id(&self) -> Result<InputId> {
        let idx = self
            .input_weighted_index
            .as_ref()
            .context("weighted input index missing")?
            .sample(&mut FastRand);

        Ok(self.input_id[idx])
    }

    fn scheduled_inputs(&self) -> impl Iterator<Item = &InputInfo> {
        self.inputs
            .values()
            .filter(|input| input.result.category().schedule())
    }

    pub(crate) fn input(&mut self, id: InputId) -> Option<&InputInfo> {
        self.inputs.get(&id)
    }

    pub(crate) fn random_stream_index(
        &mut self,
        id: InputId,
        distribution: StreamRandomDistribution,
    ) -> Option<Result<&InputContext>> {
        self.inputs.get_mut(&id).map(|info| {
            info.stream_distribution
                .random_stream_index(&info.stream_info, &info.result, distribution)
                .context("Random stream index pick failed for corpus base input")
        })
    }

    pub fn random_input(&self) -> Result<&InputInfo> {
        self.random_input_id().and_then(|id| {
            self.inputs
                .get(&id)
                .context("Input for random input id is missing")
        })
    }

    pub fn inputs(&self) -> impl Iterator<Item = &InputInfo> {
        self.input_id
            .iter()
            .map(move |id| self.inputs.get(id).expect("Input file is available"))
    }

    pub fn statistics(&mut self) -> Result<CorpusStatistics> {
        self.update_input_weights()
            .context("Failed to update input weights")?;

        let inputs = self
            .inputs
            .values()
            .map(|info| InputStatistics {
                id: info.result.input.id(),
                category: info.result.category(),
                length: info.result.input.len(),
                uniq_features: info.uniq_features.len(),
                rare_feature_frequency: info.rare_feature_frequency.clone(),
                stream_info: info.stream_info.clone(),
                mutation_count: info.mutation_count,
                child_results: info.child_results,
                weight: info.energy.unwrap_or(0.),
            })
            .collect();

        Ok(CorpusStatistics {
            edges: self.edges.len(),
            features: self
                .feature_frequency
                .iter()
                .map(|(feature, frequency)| (*feature, *frequency))
                .collect(),
            rare_features: self.rare_features.iter().copied().collect(),
            unscheduled_features: self.unscheduled_features.iter().copied().collect(),
            most_abundant_rare_feature_frequency: self.most_abundant_rare_feature().1,
            mutation_count: self.mutation_count,
            inputs,
        })
    }
}

#[derive(Debug, EnumKind)]
#[enum_kind(CorpusResultKind)]
pub enum CorpusResult {
    NewCoverage(NewCoverage),
    ShorterInput(InputResult),
    Uninteresting(InputResult),
}
#[derive(Debug)]
pub struct NewCoverage {
    result: InputResult,
    uniq_features: FxHashSet<Feature>,
}

impl NewCoverage {
    fn new(result: InputResult, uniq_features: FxHashSet<Feature>) -> Self {
        Self {
            result,
            uniq_features,
        }
    }

    pub fn into_inner(self) -> InputResult {
        self.result
    }

    pub fn result(&self) -> &InputResult {
        &self.result
    }

    pub fn uniq_features(&self) -> &FxHashSet<Feature> {
        &self.uniq_features
    }

    pub(crate) fn result_mut(&mut self) -> &mut InputResult {
        &mut self.result
    }
}

#[derive(Debug)]
pub struct InputInfo {
    result: InputResult,
    /// unique features of this input (new feature when this input was added)
    uniq_features: FxHashSet<Feature>,
    /// frequence of feature occurence in mutations based on this input
    rare_feature_frequency: FxHashMap<Feature, u16>,
    mutation_count: usize,
    child_results: [usize; InputCategory::VALID_VARIANT_COUNT],
    energy: Option<f64>,
    stream_info: StreamInfo,
    stream_distribution: StreamDistribution,
    sum_incidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamInfo {
    success: FxHashMap<InputContext, SuccessRate>,
}

impl StreamInfo {
    pub fn new(success: FxHashMap<InputContext, SuccessRate>) -> Self {
        Self { success }
    }

    pub(crate) fn success(&self) -> &FxHashMap<InputContext, SuccessRate> {
        &self.success
    }

    fn add_count<'a>(&mut self, mutation_log: impl Iterator<Item = &'a InputContext>) {
        // update stream mutation count
        for context in mutation_log {
            if let Some(success_rate) = self.success.get_mut(context) {
                success_rate.count += 1;
            }
        }
    }

    fn add_success<'a>(&mut self, mutation_log: impl Iterator<Item = &'a InputContext>) {
        // add stream mutation success
        for context in mutation_log {
            if let Some(success_rate) = self.success.get_mut(context) {
                success_rate.success += 1;
                success_rate.count += 1;
            }
        }
    }

    fn reset_success(&mut self) {
        for success_rate in self.success.values_mut() {
            success_rate.count = 1;
            success_rate.success = 1;
        }
    }
}

impl InputInfo {
    fn new(
        rare_features: usize,
        uniq_features: FxHashSet<Feature>,
        base_input: Option<&mut InputInfo>,
        result: InputResult,
    ) -> Result<InputInfo> {
        let sum_incidence = (rare_features + uniq_features.len()) as f64;
        let energy = sum_incidence.ln();

        let changed_input_streams = STREAM_DISTRIBUTION_SUCCESS
            .then(|| result.changed_input_streams(base_input.as_deref()))
            .unwrap_or_default();

        let success = STREAM_DISTRIBUTION_SUCCESS
            .then(|| {
                // base input stream mutation success
                let base = base_input.as_deref().map(|info| &info.stream_info.success);

                // collect success rate for each input stream
                result
                    .file()
                    .input_streams()
                    .keys()
                    .map(|context| {
                        // inherit from base input or create new
                        let mut success_rate = base
                            .and_then(|success| success.get(context))
                            .cloned()
                            .unwrap_or_default();

                        // add 1 for each new/changed stream
                        if changed_input_streams.contains(context) {
                            success_rate.count += 1;
                            success_rate.success += 1;
                        }

                        // assert all streams have at least one mutation/success
                        debug_assert!(success_rate.count > 0);
                        debug_assert!(success_rate.success > 0);

                        (context.clone(), success_rate)
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(InputInfo {
            result,
            uniq_features,
            rare_feature_frequency: FxHashMap::default(),
            mutation_count: 0,
            child_results: [0; InputCategory::VALID_VARIANT_COUNT],
            energy: Some(energy),
            stream_info: StreamInfo::new(success),
            stream_distribution: StreamDistribution::default(),
            sum_incidence,
        })
    }

    pub(crate) fn stream_info(&self) -> &StreamInfo {
        &self.stream_info
    }

    pub fn result(&self) -> &InputResult {
        &self.result
    }

    pub fn fork(&self) -> InputFork {
        InputFork::from_base(
            self.result.file().fork(),
            self.result.chrono_stream_init().clone(),
        )
    }

    fn remove_feature_frequency(&mut self, feature: Feature) {
        if self.rare_feature_frequency.remove(&feature).is_some() {
            self.request_energy_update();
        }
    }

    fn update_feature_frequency(&mut self, feature: Feature) {
        let frequency = self.rare_feature_frequency.entry(feature).or_default();
        *frequency = frequency.saturating_add(1);
        self.request_energy_update();
    }

    fn new_rare_feature(&mut self) {
        // apply add-one smoothing to this locally undiscovered feature
        if let Some(energy) = &mut self.energy {
            self.sum_incidence += 1.;
            *energy += self.sum_incidence.ln() / self.sum_incidence;
        }
    }

    fn request_energy_update(&mut self) {
        self.energy = None;
    }

    fn energy(
        &mut self,
        global_rare_feature_count: usize,
        average_basic_blocks: f64,
        average_mutation_count: f64,
    ) -> f64 {
        // don't schedule crashes, exit hook hits or timeouts
        if !self.result.category().schedule() {
            return 0.;
        }

        // our mutation count exceeds average mutations greater than max factor
        if self.mutation_count as f64 / MAX_MUTATION_FACTOR > average_mutation_count {
            log::trace!("mutation_count = {:?}", self.mutation_count);
            log::trace!("mutation count exceeds average mutations greater than max factor");
            return 0.;
        }

        // use cached input energy if available
        let mut energy = self.energy.unwrap_or_else(|| {
            // or calculate input energy
            self.energy_entropic(global_rare_feature_count)
        });

        // cache (raw) input energy without scaling
        self.energy = Some(energy);

        // disincentivize timeouts
        if DISINCENTIVIZE_TIMEOUTS {
            if let StopReason::LimitReached(limit) = self.result.stop_reason {
                energy *= TIMEOUT_SCALE[limit.enum_index()];
            }
        }

        // disincentivize by child results
        if DISINCENTIVIZE_BY_CHILD_RESULT {
            energy *= child_result_scale(self.mutation_count, &self.child_results);
        }

        // scale by executed basic blocks
        if SCALE_ENERGY {
            energy *= scale(self.result.basic_blocks as f64, average_basic_blocks);
        }

        energy
    }

    fn energy_entropic(&mut self, global_rare_feature_count: usize) -> f64 {
        // calculate energy
        let mut energy = 0.;
        let mut sum = 0.;

        // rare feature frequency in mutations of this input
        for frequence in self.rare_feature_frequency.values() {
            let frequence = *frequence as f64;
            energy -= (frequence + 1.) * frequence.ln_1p();
            sum += frequence + 1.;
        }

        // discovered features compared to global count
        sum += (global_rare_feature_count - self.rare_feature_frequency.len()) as f64;

        // mutation count
        let mutation_count = self.mutation_count as f64;
        energy -= (mutation_count + 1.) * mutation_count.ln_1p();
        sum += mutation_count + 1.;

        // normalize energy
        debug_assert!(sum > 0.);
        energy = (energy / sum) + sum.ln();

        log::trace!(
            "energy = {}, global_rare_feature_count = {}",
            energy,
            global_rare_feature_count
        );
        debug_assert!(energy > 0.);
        debug_assert!(energy <= (std::cmp::max(1, global_rare_feature_count) as f64).ln() + 1.);

        self.sum_incidence = sum;

        energy
    }
}

fn child_result_scale(
    mutation_count: usize,
    child_results: &[usize; InputCategory::VALID_VARIANT_COUNT],
) -> f64 {
    debug_assert_eq!(mutation_count, child_results.iter().sum::<usize>());
    debug_assert_eq!(
        CHILD_RESULT_SCALE_INV.len(),
        InputCategory::VALID_VARIANT_COUNT
    );

    // avoid div-by-zero
    if mutation_count == 0 {
        return 1.;
    }

    // sum `inverse scale * child result count`
    let inverse_scale: usize = child_results
        .iter()
        .enumerate()
        .map(|(idx, count)| CHILD_RESULT_SCALE_INV[idx] * count)
        .sum();

    // calculate average scale
    mutation_count as f64 / inverse_scale as f64
}

fn scale(count: f64, average: f64) -> f64 {
    if count > average * 10. {
        1.
    } else if count > average * 4. {
        2.5
    } else if count > average * 2. {
        5.
    } else if count * 3. > average * 4. {
        7.5
    } else if count * 4. < average {
        30.
    } else if count * 3. < average {
        20.
    } else if count * 2. < average {
        15.
    } else {
        10.
    }
}

#[derive(Clone)]
pub struct InputResult {
    input: InputFile,
    timestamp: Epoch,
    basic_blocks: usize,
    stop_reason: StopReason,
    chrono_stream: LazyTransform<Vec<InputContext>, Rc<ChronoStream>>,
}

#[derive(
    Debug, PartialEq, Eq, Hash, Clone, Copy, EnumIndex, VariantCount, Serialize, Deserialize,
)]
pub enum InputCategory {
    Input,
    Crash,
    Exit,
    Timeout,
    Invalid,
}

impl InputResult {
    pub fn new(
        input: InputFile,
        timestamp: Epoch,
        basic_blocks: usize,
        stop_reason: StopReason,
        access_log: Vec<InputContext>,
    ) -> Self {
        Self {
            input,
            timestamp,
            basic_blocks,
            stop_reason,
            chrono_stream: LazyTransform::new(access_log),
        }
    }

    pub fn as_fork(self) -> InputFork {
        InputFork::from_result(self)
    }

    pub fn into_inner(self) -> InputFile {
        self.input
    }

    fn changed_input_streams(&self, base_input: Option<&InputInfo>) -> FxHashSet<InputContext> {
        let mut changed_streams = FxHashSet::default();

        let streams = self.file().input_streams();
        let base_streams = base_input.map(|info| info.result().file().input_streams());

        for (ctx, stream) in streams {
            let len = stream.len();

            // ignore empty streams
            if len == 0 {
                continue;
            }

            // compare with base input stream
            if let Some(base_stream) = base_streams.and_then(|streams| streams.get(ctx)) {
                // NOTE: base_stream is minimized, stream not
                if len <= base_stream.len() {
                    // only compare prefix (ignore removed values)
                    if stream.as_ref()[..len] == base_stream.as_ref()[..len] {
                        continue;
                    }
                }
            }

            // either new stream or prefix changed
            changed_streams.insert(ctx.clone());
        }

        changed_streams
    }

    pub fn stop_reason(&self) -> &StopReason {
        &self.stop_reason
    }

    pub fn category(&self) -> InputCategory {
        InputCategory::from(&self.stop_reason)
    }

    fn replace_with(&mut self, mut other: Self) {
        other.input.replace_id(&self.input);
        other.timestamp = self.timestamp;
        debug_assert_eq!(other.stop_reason, self.stop_reason);
        *self = other;
    }

    pub fn file(&self) -> &InputFile {
        &self.input
    }

    pub(crate) fn file_mut(&mut self) -> &mut InputFile {
        &mut self.input
    }

    pub(crate) fn inner_ref_mut(&mut self) -> (&mut InputFile, &ChronoStream) {
        self.chrono_stream_init();
        (&mut self.input, self.chrono_stream.get().unwrap())
    }

    pub fn timestamp(&self) -> Epoch {
        self.timestamp
    }

    pub fn read_count(&self) -> usize {
        match self.chrono_stream.get() {
            Some(chrono_stream) => chrono_stream.len(),
            None => self.file().read_count(),
        }
    }

    fn chrono_stream_init(&self) -> &Rc<ChronoStream> {
        self.chrono_stream
            .get_or_create(|access_log| Rc::new(ChronoStream::from_access_log(access_log)))
    }

    pub fn chrono_stream(&self) -> &ChronoStream {
        self.chrono_stream_init()
    }
}

impl fmt::Debug for InputResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InputResult")
            .field("input", &self.input)
            .field("timestamp", &self.timestamp)
            .field("basic_blocks", &self.basic_blocks)
            .field("stop_reason", &self.stop_reason)
            .field("chrono_stream", &self.chrono_stream.get())
            .finish()
    }
}

impl From<ExecutionResult<InputFile>> for InputResult {
    fn from(result: ExecutionResult<InputFile>) -> Self {
        InputResult::new(
            result.hardware.input,
            epoch().expect("system time is available"),
            result.counts.basic_block(),
            result.stop_reason,
            result.hardware.access_log,
        )
    }
}

impl InputCategory {
    pub const VALID_VARIANT_COUNT: usize = InputCategory::VARIANT_COUNT - 1;

    pub fn schedule(self) -> bool {
        match self {
            Self::Input => SCHEDULE_INPUT,
            Self::Crash => SCHEDULE_CRASH,
            Self::Exit => SCHEDULE_EXIT,
            Self::Timeout => SCHEDULE_TIMEOUT,
            Self::Invalid => false,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Input => "input",
            Self::Crash => "crash",
            Self::Exit => "exit",
            Self::Timeout => "timeout",
            Self::Invalid => "invalid",
        }
    }
}

impl FromStr for InputCategory {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "input" => Self::Input,
            "crash" => Self::Crash,
            "exit" => Self::Exit,
            "timeout" => Self::Timeout,
            "invalid" => Self::Invalid,
            _ => anyhow::bail!("Unknown InputCategory {:?}", s),
        })
    }
}

impl fmt::Display for InputCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<&StopReason> for InputCategory {
    fn from(stop_reason: &StopReason) -> Self {
        match stop_reason {
            StopReason::EndOfInput => InputCategory::Input,
            StopReason::Crash { .. }
            | StopReason::NonExecutable { .. }
            | StopReason::RomWrite { .. } => InputCategory::Crash,
            StopReason::LimitReached(_) | StopReason::InfiniteSleep => InputCategory::Timeout,
            StopReason::ExitHook
            | StopReason::Script
            | StopReason::Reset
            | StopReason::Shutdown
            | StopReason::Panic
            | StopReason::Abort => InputCategory::Exit,
            StopReason::UserExitRequest => InputCategory::Invalid,
        }
    }
}
