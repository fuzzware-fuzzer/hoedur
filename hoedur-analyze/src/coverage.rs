use std::{io::BufRead, path::Path};

use anyhow::{Context, Result};
use common::{fs::bufreader, FxHashSet};
use hoedur::coverage::CoverageReport;
use qemu_rs::Address;

pub type BasicBlockList = FxHashSet<Address>;

#[derive(Debug, Default)]
pub struct Filter {
    pub include: Option<BasicBlockList>,
}

impl Filter {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn with_include(path: &Path) -> Result<Self> {
        Ok(Self {
            include: Some(read_basic_block_list(path)?),
        })
    }
}

fn read_basic_block_list(path: &Path) -> Result<BasicBlockList> {
    let mut basic_blocks = FxHashSet::default();

    for line in bufreader(path).context("Failed to read filter")?.lines() {
        let line = line?;
        if !line.is_empty() {
            basic_blocks.insert(
                Address::from_str_radix(&line, 16)
                    .with_context(|| format!("Failed to parse {line:?} as hex number"))?,
            );
        }
    }

    Ok(basic_blocks)
}

pub trait CoverageReportExt {
    fn to_superset(
        &self,
        basic_block_filter: &Filter,
        bugs_filter: Option<&[&str]>,
    ) -> FxHashSet<Address>;
    fn to_plot(&self, filter: &Filter, filter_bugs: Option<&[&str]>) -> Vec<(u64, usize)>;
}

impl CoverageReportExt for CoverageReport {
    fn to_superset(
        &self,
        basic_block_filter: &Filter,
        bugs_filter: Option<&[&str]>,
    ) -> FxHashSet<Address> {
        let mut superset = FxHashSet::default();

        for input in self
            .inputs()
            .iter()
            .filter(|coverage| coverage.is_valid(bugs_filter))
        {
            // collect coverage superset
            for pc in input.coverage() {
                if let Some(include) = &basic_block_filter.include {
                    if !include.contains(pc) {
                        continue;
                    }
                }

                superset.insert(*pc);
            }
        }

        superset
    }

    fn to_plot(
        &self,
        basic_block_filter: &Filter,
        filter_bugs: Option<&[&str]>,
    ) -> Vec<(u64, usize)> {
        let mut points = Vec::with_capacity(self.inputs().len());
        let mut superset = FxHashSet::default();
        let mut coverage = 0;
        let mut coverage_start = false;

        for input in self
            .inputs()
            .iter()
            .filter(|coverage| coverage.is_valid(filter_bugs))
        {
            // collect coverage superset
            for pc in input.coverage() {
                if let Some(include) = &basic_block_filter.include {
                    if !include.contains(pc) {
                        continue;
                    }
                }

                superset.insert(*pc);
            }

            // current input timestamp
            let timestamp = input.timestamp().unwrap_or(0);

            // new coverage found => add start point
            if superset.len() > coverage {
                coverage = superset.len();
                coverage_start = true;

                match points.last_mut() {
                    // update coverage for existing data point at timestamp
                    Some((last_timestamp, last_coverage)) if *last_timestamp == timestamp => {
                        *last_coverage = coverage;
                    }
                    // push new data point
                    _ => points.push((timestamp, coverage)),
                }
            }
            // coverage unchanged, timestamp changed => add/update end point
            else if Some(timestamp) != points.last().map(|(timestamp, _)| timestamp).copied() {
                // no end point => create end point
                if coverage_start {
                    coverage_start = false;
                    points.push((timestamp, coverage));
                }
                // end point exists => update end point timestamp
                else {
                    let (last_timestamp, last_coverage) =
                        points.last_mut().expect("Plot contains points");
                    assert_eq!(coverage, *last_coverage, "coverage did not change");

                    // update end point timestamp
                    *last_timestamp = timestamp;
                }
            }
        }

        points
    }
}
