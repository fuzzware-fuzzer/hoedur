use std::{fmt::Debug, num::NonZeroUsize, usize};

use anyhow::{Context, Result};
use frametracer::{symbolizer::Symbolizer, Address};
use itertools::Itertools;
use modeling::{
    hardware::{Hardware, Input, Interrupt},
    input::{
        value::{InputValue, InputValueType},
        InputContext, StreamContext,
    },
};
use serde::{Deserialize, Serialize};

use crate::{arch::ArchEmulator, hooks::HookTarget, EmulatorCounts};

#[derive(Debug, Clone)]
pub struct EmulatorInterruptConfig {
    mode: InterruptMode,
    trigger: InterruptTrigger,
    allowlist: Option<Vec<Interrupt>>,
    blocklist: Option<Vec<Interrupt>>,
    index: usize,
    last_interrupt: usize,
}

#[derive(Debug, Clone)]
pub struct EmulatorInterruptConfigSnapshot {
    index: usize,
    last_interrupt: usize,
}

impl From<TargetInterruptConfig> for EmulatorInterruptConfig {
    fn from(config: TargetInterruptConfig) -> Self {
        Self {
            mode: config.mode,
            trigger: config.trigger.into(),
            allowlist: config.allowlist,
            blocklist: config.blocklist,
            index: 0,
            last_interrupt: 0,
        }
    }
}

impl From<TargetInterruptTrigger> for InterruptTrigger {
    fn from(trigger: TargetInterruptTrigger) -> Self {
        Self {
            on_infinite_sleep: trigger.on_infinite_sleep,
            interval: trigger.interval.into(),
            custom: trigger.custom.unwrap_or_default(),
        }
    }
}

impl EmulatorInterruptConfig {
    pub(crate) fn custom_trigger(&self, symbolizer: &Symbolizer) -> Result<Vec<Address>> {
        self.trigger
            .custom
            .iter()
            .map(|trigger| trigger.target.resolve(symbolizer))
            .flatten_ok()
            .collect::<Result<Vec<_>>>()
            .context("Failed to resolve custom interrupt trigger addresses")
    }

    pub(crate) fn next_interval(&self, counts: &EmulatorCounts) -> Option<usize> {
        self.trigger
            .interval
            .map(|interval| interval.get() - (counts.basic_block - self.last_interrupt))
    }

    pub(crate) fn next_interrupt<I: Input + Debug>(
        &mut self,
        arch: &ArchEmulator,
        counts: &EmulatorCounts,
        hardware: &mut Hardware<I>,
        force_raise: bool,
    ) -> Option<Interrupt> {
        let irqs = arch.available_interrupts(force_raise);
        log::trace!("available irqs = {:?}", irqs);

        let irqs = self.apply_filter(irqs);
        log::trace!("available filtered irqs = {:?}", irqs);

        // set last interrupt (even when no interrupt will be raised)
        self.last_interrupt = counts.basic_block;

        if irqs.is_empty() {
            return None;
        }

        match self.mode {
            InterruptMode::Disabled => None,
            InterruptMode::RoundRobin => {
                let irq = irqs[self.index % irqs.len()];
                self.index += 1;
                Some(irq)
            }
            InterruptMode::Fuzzed => {
                if irqs.len() == 1 {
                    // only one interrupt available
                    Some(irqs[0])
                } else {
                    // use fuzzer input
                    hardware
                        .input_read(InputContext::new(
                            StreamContext::Interrupt,
                            InputValueType::Choice(irqs.len() as u8),
                        ))
                        .map(|value| match value.as_ref() {
                            InputValue::Choice { index, .. } => irqs[*index as usize],
                            _ => unreachable!(),
                        })
                }
            }
        }
    }

    fn apply_filter(&self, irqs: Vec<Interrupt>) -> Vec<Interrupt> {
        // no filters
        if self.blocklist.is_none() && self.allowlist.is_none() {
            return irqs;
        }

        irqs.into_iter()
            .filter(|irq| {
                // filter when in blocklist
                if let Some(blocklist) = &self.blocklist {
                    if blocklist.contains(irq) {
                        return false;
                    }
                }

                // allowlist exists
                if let Some(allowlist) = &self.allowlist {
                    // filter when not in allowlist
                    if !allowlist.contains(irq) {
                        return false;
                    }
                }

                true
            })
            .collect()
    }

    pub fn snapshot_create(&self) -> EmulatorInterruptConfigSnapshot {
        EmulatorInterruptConfigSnapshot {
            index: self.index,
            last_interrupt: self.last_interrupt,
        }
    }

    pub fn snapshot_restore(&mut self, snapshot: &EmulatorInterruptConfigSnapshot) {
        self.index = snapshot.index;
        self.last_interrupt = snapshot.last_interrupt;
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InterruptMode {
    Disabled,
    RoundRobin,
    Fuzzed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct InterruptTrigger {
    on_infinite_sleep: bool,
    interval: Option<NonZeroUsize>,
    custom: Vec<CustomInterruptTrigger>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TargetInterruptConfig {
    #[serde(default = "Default::default")]
    mode: InterruptMode,
    #[serde(default = "Default::default")]
    trigger: TargetInterruptTrigger,
    #[serde(alias = "whitelist")]
    allowlist: Option<Vec<Interrupt>>,
    #[serde(alias = "blacklist")]
    blocklist: Option<Vec<Interrupt>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TargetInterruptTrigger {
    #[serde(default = "default_on_infinite_sleep")]
    on_infinite_sleep: bool,
    #[serde(default = "default_interval")]
    interval: TargetInterruptInterval,
    custom: Option<Vec<CustomInterruptTrigger>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TargetInterruptInterval {
    Enabled(bool),
    BasicBlock(usize),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CustomInterruptTrigger {
    name: Option<String>,
    #[serde(flatten)]
    target: HookTarget,
    // # mode:
    // # allowlist / blocklist
}

impl Default for InterruptMode {
    fn default() -> Self {
        Self::RoundRobin
    }
}

impl Default for TargetInterruptTrigger {
    fn default() -> Self {
        Self {
            on_infinite_sleep: default_on_infinite_sleep(),
            interval: default_interval(),
            custom: None,
        }
    }
}

fn default_on_infinite_sleep() -> bool {
    true
}

fn default_interval() -> TargetInterruptInterval {
    TargetInterruptInterval::BasicBlock(1_000)
}

impl TargetInterruptConfig {
    pub fn new(
        mode: InterruptMode,
        trigger: TargetInterruptTrigger,
        allowlist: Option<Vec<Interrupt>>,
        blocklist: Option<Vec<Interrupt>>,
    ) -> Self {
        Self {
            mode,
            trigger,
            allowlist,
            blocklist,
        }
    }
}

impl TargetInterruptTrigger {
    pub fn new(
        on_infinite_sleep: bool,
        interval: TargetInterruptInterval,
        custom: Option<Vec<CustomInterruptTrigger>>,
    ) -> Self {
        Self {
            on_infinite_sleep,
            interval,
            custom,
        }
    }
}

impl Into<Option<NonZeroUsize>> for TargetInterruptInterval {
    fn into(self) -> Option<NonZeroUsize> {
        match self {
            TargetInterruptInterval::Enabled(enabled) if !enabled => None,
            TargetInterruptInterval::Enabled(_) => default_interval().into(),
            TargetInterruptInterval::BasicBlock(interval) => NonZeroUsize::new(interval),
        }
    }
}

impl CustomInterruptTrigger {
    pub fn new(name: Option<String>, target: HookTarget) -> Self {
        Self { name, target }
    }
}
