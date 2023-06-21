use std::sync::atomic::Ordering;

use log::Level;
use qemu_sys::{tcg::TcgCallback, tcg_function};

use crate::{
    coverage,
    hook::{hooks, is_exit, is_nx, set_pc},
    interrupt::inject_interrupt,
    lut::{clear_last_io, set_last_io},
    qemu::{handle_stop_request, QEMU_RUNNING},
    Address,
};

static mut NEXT_BASIC_BLOCK_HOOK: u64 = 0;

pub fn set_next_basic_block_hook(bb_count: u64) {
    log::trace!("set_next_basic_block_hook(bb_count = {})", bb_count);

    unsafe {
        NEXT_BASIC_BLOCK_HOOK = bb_count;
    }
}

pub fn get_next_basic_block_hook() -> u64 {
    let bb_count = unsafe { NEXT_BASIC_BLOCK_HOOK };
    log::trace!("get_next_basic_block_hook() = {}", bb_count);

    bb_count
}

extern "C" fn tb_start_hook_rs(
    db_ptr: *mut qemu_sys::DisasContextBase,
) -> *mut qemu_sys::TCGHelperInfo {
    let db = unsafe { db_ptr.as_ref() }.expect("DisasContextBase is not null");
    let pc = db.pc_next as Address;

    log::trace!("tb_start_hook_rs() db = {:#x?}", db);

    if is_exit(pc) {
        EXIT_HOOK_INFO.as_callback()
    } else if is_nx(pc) {
        NX_HOOK_INFO.as_callback()
    } else {
        // warn about CF_LAST_IO (only in debug builds)
        let tb = unsafe { db.tb.as_ref() }.expect("TranslationBlock is not null");
        let last_io = tb.cflags & qemu_sys::CF_LAST_IO != 0;
        let level = if last_io { Level::Debug } else { Level::Trace };
        log::log!(
            level,
            "tb_start_hook_rs(tb_ptr = {:#x?}): pc = {:#x?}, cflags = {:x?} & CF_LAST_IO = {:?}",
            db.tb,
            pc,
            tb.cflags,
            last_io
        );

        if last_io {
            set_last_io(tb)
        } else {
            clear_last_io(tb)
        }

        BASIC_BLOCK_HOOK_INFO.as_callback()
    }
}

tcg_function! {
    qemu_sys::TCG_CALL_NO_WRITE_GLOBALS;

    pub(crate) fn basic_block_hook(pc: u64) {
        let next_hook = unsafe { NEXT_BASIC_BLOCK_HOOK.wrapping_sub(1) };
        unsafe { NEXT_BASIC_BLOCK_HOOK = next_hook };

        if next_hook == 0 {
            basic_block_hook_extended(pc);
        } else {
            coverage::add_basic_block(pc);
        }
    }
}

#[cold]
#[inline(never)]
fn basic_block_hook_extended(pc: u64) {
    log::trace!("basic_block_hook(pc = {:#x?})", pc);
    assert!(QEMU_RUNNING.load(Ordering::SeqCst));
    let pc = pc as Address;

    set_pc(pc);
    hooks().on_basic_block(pc).expect("basic block hook failed");
    handle_stop_request();
    inject_interrupt();
}

tcg_function! {
    qemu_sys::TCG_CALL_NO_WRITE_GLOBALS;

    pub(super) fn interrupt_trigger(pc: u64) {
        log::trace!("interrupt_trigger(pc = {pc:#x?})");
        assert!(QEMU_RUNNING.load(Ordering::SeqCst));
        let pc = pc as Address;

        set_pc(pc);
        hooks().on_interrupt_trigger(pc).expect("interrupt trigger hook failed");
        handle_stop_request();
        inject_interrupt();
    }
}

tcg_function! {
    qemu_sys::TCG_CALL_NO_WRITE_GLOBALS;

    pub(super) fn exit_hook(pc: u64) {
        log::trace!("exit_hook(pc = {:#x?})", pc);
        assert!(QEMU_RUNNING.load(Ordering::SeqCst));
        let pc = pc as Address;

        set_pc(pc);
        hooks().on_exit(pc).expect("exit hook failed");
        handle_stop_request();
        assert!(!QEMU_RUNNING.load(Ordering::SeqCst));
    }
}

tcg_function! {
    qemu_sys::TCG_CALL_NO_WRITE_GLOBALS;

    pub(super) fn nx_hook(pc: u64) {
        log::trace!("nx_hook(pc = {:#x?})", pc);
        assert!(QEMU_RUNNING.load(Ordering::SeqCst));
        let pc = pc as Address;

        set_pc(pc);
        hooks().on_nx(pc).expect("nx hook failed");
        handle_stop_request();
        assert!(!QEMU_RUNNING.load(Ordering::SeqCst));
    }
}

pub(super) fn register_hooks() {
    BASIC_BLOCK_HOOK_INFO.register();
    INTERRUPT_TRIGGER_INFO.register();
    EXIT_HOOK_INFO.register();
    NX_HOOK_INFO.register();

    unsafe {
        qemu_sys::tb_start_hook = Some(tb_start_hook_rs);
    }
}
