use std::hash::Hash;

use anyhow::{Context, Result};
use common::{
    config::fuzzer::{
        SUCCESS_DISTRIBUTION_LN_MUTATIONS, SUCCESS_DISTRIBUTION_LN_SUCCESSES,
        SUCCESS_DISTRIBUTION_SCALE,
    },
    random::FastRand,
    FxHashMap,
};
use enum_index_derive::{EnumIndex, IndexEnum};
use modeling::input::{stream::InputStream, InputContext};
use rand::prelude::*;
use rand_distr::{Uniform, WeightedAliasIndex};
use serde::{Deserialize, Serialize};
use variant_count::VariantCount;

use crate::{corpus::StreamInfo, statistics::SuccessRate, InputResult};

#[derive(
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    Copy,
    EnumIndex,
    IndexEnum,
    VariantCount,
    Serialize,
    Deserialize,
)]
pub enum StreamRandomDistribution {
    Uniform,
    Success,
}

#[derive(Debug, Default, Clone)]
pub struct StreamDistribution {
    context: Option<Vec<InputContext>>,
    uniform: Option<Uniform<usize>>,
    success: Option<WeightedAliasIndex<f64>>,
}

impl StreamDistribution {
    pub(crate) fn request_success_update(&mut self) {
        self.success = None;
    }

    pub fn random_stream_index(
        &mut self,
        info: &StreamInfo,
        result: &InputResult,
        distribution: StreamRandomDistribution,
    ) -> Result<&InputContext> {
        let input_streams = result.file().input_streams();

        // empty input has no streams
        debug_assert!(!self.context(input_streams).is_empty());

        let index = match distribution {
            StreamRandomDistribution::Uniform => self.uniform(input_streams).sample(&mut FastRand),
            StreamRandomDistribution::Success => self
                .success(input_streams, info.success())?
                .sample(&mut FastRand),
        };

        Ok(&self.context(input_streams)[index])
    }

    fn context(&mut self, input_streams: &FxHashMap<InputContext, InputStream>) -> &[InputContext] {
        self.context
            .get_or_insert_with(|| input_streams.keys().cloned().collect())
    }

    fn uniform(&mut self, input_streams: &FxHashMap<InputContext, InputStream>) -> &Uniform<usize> {
        self.uniform
            .get_or_insert_with(|| Uniform::new(0, input_streams.len()))
    }

    fn success(
        &mut self,
        input_streams: &FxHashMap<InputContext, InputStream>,
        stream_mutation_success: &FxHashMap<InputContext, SuccessRate>,
    ) -> Result<&WeightedAliasIndex<f64>> {
        if self.success.is_none() {
            self.success = Some(
                WeightedAliasIndex::new(
                    self.context(input_streams)
                        .iter()
                        .map(|ctx| {
                            let scale = if let Some(scale) = SUCCESS_DISTRIBUTION_SCALE {
                                input_streams.get(ctx).unwrap().scaled_size_by(scale) as f64
                            } else {
                                1.
                            };

                            let success_rate = stream_mutation_success
                                .get(ctx)
                                .map(|stream| {
                                    let success = stream.success as f64;
                                    let success = if SUCCESS_DISTRIBUTION_LN_SUCCESSES {
                                        success.ln_1p()
                                    } else {
                                        success
                                    };

                                    let count = stream.count as f64;
                                    let count = if SUCCESS_DISTRIBUTION_LN_MUTATIONS {
                                        count.ln_1p()
                                    } else {
                                        count
                                    };

                                    success / count
                                })
                                // NOTE: without mutation stacking new input streams can be found during mutation
                                .unwrap_or(1.);

                            success_rate * scale
                        })
                        .collect(),
                )
                .context("Failed to create a weighted index distribution by stream success.")?,
            )
        }

        Ok(self.success.as_ref().unwrap())
    }
}
