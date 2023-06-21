use std::{
    cell::{RefCell, RefMut},
    sync::Arc,
};

use anyhow::Result;

mod fuzz {
    pub(crate) mod board;
    pub(crate) mod machine;
    pub(crate) mod tcg;
}

mod arch;
mod hook;
mod interrupt;
mod lut;
mod qcontrol;
mod qemu;
mod snapshot;

pub mod coverage;
pub mod memory;

pub use arch::*;
pub use hook::basic_block::{get_next_basic_block_hook, set_next_basic_block_hook};
pub use interrupt::request_interrupt_injection;
pub use qcontrol::{MemoryBlock, QemuStateControl};
pub use qemu::{drop, init_qemu, request_stop, run, set_signal_handler, QemuStopReason};
pub use snapshot::{MemorySnapshot, MmioRewound, Snapshot};

pub type USize = u32;
pub type ISize = i32;
pub type Address = USize;
pub type MmioAddress = Address;

pub trait RegisterAccess {
    fn read(&self, register: Register) -> Address;
    fn write(&mut self, register: Register, value: Address);
}

pub type QemuCallbackShared = Arc<RefCell<dyn QemuCallback>>;
pub type QemuCallbackGuard<'a> = RefMut<'a, dyn QemuCallback>;

pub trait QemuCallback {
    /// on each basic block when --NEXT_BASIC_BLOCK_HOOK == 0
    fn on_basic_block(&mut self, pc: Address) -> Result<()>;
    /// on instruction when in trace-mode
    fn on_instruction(&mut self, pc: Address) -> Result<()>;
    /// on interrupt trigger
    fn on_interrupt_trigger(&mut self, pc: Address) -> Result<()>;
    /// on instruction with debug hook
    fn on_debug(&mut self, pc: Address) -> Result<()>;
    /// on instruction with exit hook
    fn on_exit(&mut self, pc: Address) -> Result<()>;
    /// on instruction in non-executable region
    fn on_nx(&mut self, pc: Address) -> Result<()>;
    /// when firmware waits for an interrupt
    fn on_wait_for_interrupt(&mut self, halted: bool) -> Result<()>;
    /// on cpu exception, can be catched
    fn on_exception(&mut self, exception: Exception) -> Result<bool>;

    /// on MMIO read
    fn on_read(&mut self, pc: Address, addr: Address, size: u8) -> Result<u64>;
    /// on MMIO write
    fn on_write(&mut self, pc: Address, addr: Address, data: u64, size: u8) -> Result<()>;

    /// on RAM read
    fn on_ram_read(&mut self, pc: Address, addr: Address, data: u64, size: u8) -> Result<()>;
    /// on RAM write
    fn on_ram_write(&mut self, pc: Address, addr: Address, data: u64, size: u8) -> Result<()>;

    /// on ROM read
    fn on_rom_read(&mut self, pc: Address, addr: Address, data: u64, size: u8) -> Result<()>;
    /// on ROM write
    fn on_rom_write(&mut self, pc: Address, addr: Address, data: u64, size: u8) -> Result<()>;

    /// on state update (currently SysTick)
    fn on_update(&mut self, event: Event) -> Result<()>;

    /// QEMU abort (crash)
    fn on_abort(&mut self) -> Result<()>;
}

pub fn qcontrol<'a>() -> &'a QemuStateControl {
    QemuStateControl::get_ref()
}

pub fn qcontrol_mut<'a>() -> &'a mut QemuStateControl {
    QemuStateControl::get_mut()
}
