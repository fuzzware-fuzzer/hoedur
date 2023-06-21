use std::sync::atomic::Ordering;

use anyhow::{bail, Result};
use once_cell::sync::OnceCell;

use crate::{
    interrupt::inject_interrupt, lut::PcLookupTable, qcontrol, qemu::QEMU_RUNNING, Address,
    QemuCallbackGuard, QemuCallbackShared,
};

mod abort;
mod instruction;
mod memory;

pub(crate) mod basic_block;
pub(crate) mod interrupt;
pub(crate) mod mmio;

static mut QEMU_CALLBACK: OnceCell<QemuCallbackShared> = OnceCell::new();
static INTERRUPT_TRIGGER: OnceCell<Vec<Address>> = OnceCell::new();
static EXIT_HOOKS: OnceCell<Vec<Address>> = OnceCell::new();
static DEBUG_HOOKS: OnceCell<Vec<Address>> = OnceCell::new();

pub(crate) fn hooks<'a>() -> QemuCallbackGuard<'a> {
    unsafe { QEMU_CALLBACK.get() }
        .expect("QEMU hook is initialized")
        .borrow_mut()
}

pub fn wait_for_interrupt(halted: bool) {
    log::trace!("wait_for_interrupt(halted = {:?})", halted);
    assert!(QEMU_RUNNING.load(Ordering::SeqCst));
    debug_assert!(
        (crate::qcontrol::cpu().parent_obj.halted != 0) == halted,
        "CPU is unexpectedly halted on wait-for-interrupt"
    );

    hooks()
        .on_wait_for_interrupt(halted)
        .expect("wait for interrupt hook failed");

    inject_interrupt();
}

extern "C" fn tb_flush_hook_rs() {
    log::debug!("tb_flush_hook_rs()");
    PcLookupTable::lock().clear();
}

fn set_pc(pc: Address) {
    crate::qcontrol_mut().set_register(crate::Register::PC, pc);
}

pub(crate) fn drop_qemu_hook() -> Result<()> {
    if unsafe { QEMU_CALLBACK.take() }.is_none() {
        bail!("QEMU hook not found, this should never happen!");
    }

    Ok(())
}
fn is_interrupt_hook(pc: Address) -> bool {
    INTERRUPT_TRIGGER
        .get()
        .expect("interrupt hooks are initialized")
        .binary_search(&pc)
        .is_ok()
}

fn is_exit(pc: Address) -> bool {
    EXIT_HOOKS
        .get()
        .expect("exit hooks are initialized")
        .binary_search(&pc)
        .is_ok()
}

fn is_debug(pc: Address) -> bool {
    DEBUG_HOOKS
        .get()
        .map(|hooks| hooks.binary_search(&pc).is_ok())
        .unwrap_or(false)
}

fn is_nx(pc: Address) -> bool {
    qcontrol()
        .memory()
        .iter()
        .filter_map(|mem| mem.inner().executable(pc))
        .any(|exectuable| !exectuable)
}

pub(crate) fn register_hooks(
    callback: QemuCallbackShared,
    interrupt_trigger: Vec<Address>,
    exit_hooks: Vec<Address>,
    debug_hooks: Option<Vec<Address>>,
    trace_mode: bool,
) -> Result<()> {
    // register hooks
    abort::register_hooks()?;
    basic_block::register_hooks();
    instruction::register_hooks(trace_mode);
    memory::register_hooks(trace_mode);
    unsafe {
        qemu_sys::tb_flush_hook = Some(tb_flush_hook_rs);
    }

    // ARM specific hooks
    #[cfg(feature = "arm")]
    {
        crate::nvic::register_nvic_abort_hook();
        crate::exception_level::register_change_hook();
    }

    // set hook callback
    unsafe { QEMU_CALLBACK.set(callback) }.or_else(|_| bail!("Failed to set QEMU hook"))?;

    // set exit/debug hooks
    set_hooks(&INTERRUPT_TRIGGER, interrupt_trigger)?;
    set_hooks(&EXIT_HOOKS, exit_hooks)?;
    if let Some(debug_hooks) = debug_hooks {
        set_hooks(&DEBUG_HOOKS, debug_hooks)?;
    }

    Ok(())
}

fn set_hooks(global: &OnceCell<Vec<Address>>, mut hooks: Vec<u32>) -> Result<()> {
    hooks.sort_unstable();
    hooks.dedup();

    global
        .set(hooks)
        .or_else(|_| bail!("Failed to initialize debug hooks"))
}
