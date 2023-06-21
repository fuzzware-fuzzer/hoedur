use std::sync::atomic::Ordering;

use qemu_sys::{tcg::TcgCallback, tcg_function};

use crate::{
    hook::{
        basic_block::{EXIT_HOOK_INFO, INTERRUPT_TRIGGER_INFO, NX_HOOK_INFO},
        hooks, is_debug, is_exit, is_interrupt_hook, is_nx, set_pc,
    },
    qemu::{handle_stop_request, QEMU_RUNNING},
    Address,
};

tcg_function! {
    qemu_sys::TCG_CALL_NO_WRITE_GLOBALS;

    pub(super) fn insn_trace_hook(pc: u64) {
        log::trace!("insn_trace_hook(pc = {:#x?})", pc);
        assert!(QEMU_RUNNING.load(Ordering::SeqCst));
        let pc = pc as Address;

        // always set PC, used in memory access hook
        set_pc(pc);

        if is_debug(pc) {
            hooks().on_debug(pc).expect("debug hook failed");
        }

        if is_exit(pc) {
            hooks().on_exit(pc).expect("exit hook failed");
        } else if is_nx(pc) {
            hooks().on_nx(pc).expect("nx hook failed");
        } else {
            if is_interrupt_hook(pc) {
                hooks().on_interrupt_trigger(pc).expect("interrupt trigger hook failed");
            }
            hooks().on_instruction(pc).expect("instruction trace hook failed");
        }

        handle_stop_request();
    }
}

tcg_function! {
    qemu_sys::TCG_CALL_NO_WRITE_GLOBALS;

    pub(super) fn debug_hook(pc: u64) {
        log::trace!("debug_hook(pc = {:#x?})", pc);
        assert!(QEMU_RUNNING.load(Ordering::SeqCst));
        let pc = pc as Address;

        set_pc(pc);
        hooks().on_debug(pc).expect("debug hook failed");

        if is_exit(pc) {
            hooks().on_exit(pc).expect("exit hook failed");
        } else if is_nx(pc) {
            hooks().on_nx(pc).expect("nx hook failed");
        } else if is_interrupt_hook(pc) {
            hooks().on_interrupt_trigger(pc).expect("interrupt trigger hook failed");
        }

        handle_stop_request();
    }
}

extern "C" fn insn_start_hook_trace_rs(
    db_ptr: *mut qemu_sys::DisasContextBase,
) -> *mut qemu_sys::TCGHelperInfo {
    let db = unsafe { db_ptr.as_ref() }.expect("DisasContextBase is not null");
    log::trace!("insn_start_hook_trace_rs() db = {:#x?}", db);

    INSN_TRACE_HOOK_INFO.as_callback()
}

extern "C" fn insn_start_hook_rs(
    db_ptr: *mut qemu_sys::DisasContextBase,
) -> *mut qemu_sys::TCGHelperInfo {
    let db = unsafe { db_ptr.as_ref() }.expect("DisasContextBase is not null");
    let pc = db.pc_next as Address;
    log::trace!("insn_start_hook_rs() db = {:#x?}", db);

    if is_debug(pc) {
        DEBUG_HOOK_INFO.as_callback()
    } else if is_exit(pc) {
        EXIT_HOOK_INFO.as_callback()
    } else if is_nx(pc) {
        NX_HOOK_INFO.as_callback()
    } else if is_interrupt_hook(pc) {
        INTERRUPT_TRIGGER_INFO.as_callback()
    } else {
        qemu_sys::tcg::no_callback()
    }
}

pub(super) fn register_hooks(trace_mode: bool) {
    INSN_TRACE_HOOK_INFO.register();
    DEBUG_HOOK_INFO.register();

    let insn_start_hook = if trace_mode {
        insn_start_hook_trace_rs
    } else {
        insn_start_hook_rs
    };

    unsafe {
        qemu_sys::insn_start_hook = Some(insn_start_hook);
    }
}
