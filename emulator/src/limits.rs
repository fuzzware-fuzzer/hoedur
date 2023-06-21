use common::config::emulator::limits::{
    DEFAULT_BASIC_BLOCKS, DEFAULT_INPUT_READ_OVERDUE, DEFAULT_INTERRUPTS, DEFAULT_MMIO_READ,
};
use modeling::fuzzware;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct EmulatorLimits {
    pub(super) basic_blocks: Option<usize>,
    pub(super) interrupts: Option<usize>,
    pub(super) mmio_read: Option<usize>,
    pub(super) input_read_overdue: Option<usize>,
}

impl EmulatorLimits {
    pub fn new() -> Self {
        Self {
            basic_blocks: Some(default_basic_blocks()),
            interrupts: None,
            mmio_read: None,
            input_read_overdue: None,
        }
    }

    pub fn none() -> Self {
        Self {
            basic_blocks: None,
            interrupts: None,
            mmio_read: None,
            input_read_overdue: None,
        }
    }

    pub fn basic_blocks(mut self, basic_blocks: usize) -> Self {
        self.basic_blocks = Some(basic_blocks);
        self
    }

    pub fn interrupts(mut self, interrupts: usize) -> Self {
        self.interrupts = Some(interrupts);
        self
    }

    pub fn mmio_read(mut self, mmio_read: usize) -> Self {
        self.mmio_read = Some(mmio_read);
        self
    }

    pub fn input_read_overdue(mut self, input_read_overdue: usize) -> Self {
        self.input_read_overdue = Some(input_read_overdue);
        self
    }
}

impl Default for EmulatorLimits {
    fn default() -> Self {
        Self::new()
    }
}

impl From<TargetLimits> for EmulatorLimits {
    fn from(config: TargetLimits) -> Self {
        Self {
            basic_blocks: as_option(config.basic_blocks),
            interrupts: as_option(config.interrupts),
            mmio_read: as_option(config.mmio_read),
            input_read_overdue: as_option(config.input_read_overdue),
        }
    }
}

fn as_option(value: usize) -> Option<usize> {
    if value == 0 {
        None
    } else {
        Some(value)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TargetLimits {
    #[serde(default = "default_basic_blocks")]
    basic_blocks: usize,
    #[serde(default = "default_interrupts")]
    interrupts: usize,
    #[serde(default = "default_mmio_read")]
    mmio_read: usize,
    #[serde(default = "default_input_read_overdue")]
    input_read_overdue: usize,
}

fn default_basic_blocks() -> usize {
    DEFAULT_BASIC_BLOCKS
}
fn default_interrupts() -> usize {
    DEFAULT_INTERRUPTS
}
fn default_mmio_read() -> usize {
    DEFAULT_MMIO_READ
}
fn default_input_read_overdue() -> usize {
    DEFAULT_INPUT_READ_OVERDUE
}

impl Default for TargetLimits {
    fn default() -> Self {
        Self {
            basic_blocks: default_basic_blocks(),
            interrupts: default_interrupts(),
            mmio_read: default_mmio_read(),
            input_read_overdue: default_input_read_overdue(),
        }
    }
}

impl TargetLimits {
    pub fn from_fuzzware(limits: fuzzware::config::Limits) -> Self {
        Self {
            basic_blocks: limits.translation_blocks.unwrap_or(0),
            interrupts: limits.interrupts.unwrap_or(0),
            mmio_read: 0,
            input_read_overdue: limits.fuzz_consumption_timeout.unwrap_or(0),
        }
    }
}
