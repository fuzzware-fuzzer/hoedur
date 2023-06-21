use std::fmt;

use derive_more::{Add, AddAssign, Sub, SubAssign};
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Default, Add, AddAssign, Sub, SubAssign, PartialEq, Eq, Clone, Serialize, Deserialize,
)]
pub struct EmulatorCounts {
    pub(super) basic_block: usize,
    pub(super) interrupt: usize,
    pub(super) mmio_read: usize,
    pub(super) mmio_write: usize,
}

impl fmt::Display for EmulatorCounts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:>9} basic blocks, {:>6} interrupts, {:>6} MMIO reads, {:>6} MMIO writes",
            self.basic_block, self.interrupt, self.mmio_read, self.mmio_write
        )
    }
}

impl EmulatorCounts {
    pub fn new(basic_block: usize, interrupt: usize, mmio_read: usize, mmio_write: usize) -> Self {
        Self {
            basic_block,
            interrupt,
            mmio_read,
            mmio_write,
        }
    }

    pub fn basic_block(&self) -> usize {
        self.basic_block
    }

    pub fn interrupt(&self) -> usize {
        self.interrupt
    }

    pub fn mmio_read(&self) -> usize {
        self.mmio_read
    }

    pub fn mmio_write(&self) -> usize {
        self.mmio_write
    }
}
