use std::sync::atomic::Ordering;

use crate::{hook::hooks, qemu::QEMU_RUNNING};

static mut DO_INTERRUPT: Option<unsafe extern "C" fn(cpu: *mut qemu_sys::CPUState)> = None;
static mut TCG_OPS: Option<qemu_sys::TCGCPUOps> = None;

extern "C" fn do_interrupt_hook(cs: *mut qemu_sys::CPUState) {
    let exception = unsafe { (*cs).exception_index };
    log::trace!("do_interrupt_hook(exception = {:#x?})", exception);
    assert!(QEMU_RUNNING.load(Ordering::SeqCst));

    let forward = hooks()
        .on_exception(exception.into())
        .expect("exception hook failed");

    let cpu_stop = unsafe { (*cs).stop };

    if forward && !cpu_stop {
        log::trace!("forward interrupt {:?}", exception);
        unsafe {
            let do_interrupt = DO_INTERRUPT
                .as_ref()
                .expect("do_interrupt_hook with empty do_interrupt called");

            do_interrupt(cs)
        }
    } else {
        log::debug!(
            "interrupt {:?} swallowed: forward = {}, cpu_stop = {}",
            exception,
            forward,
            cpu_stop
        );
    }
}

pub fn set_do_interrupt_hook(cpu: *const crate::fuzz::machine::Cpu) {
    let cc = unsafe {
        let obj = (cpu as *mut qemu_sys::Object)
            .as_mut()
            .expect("cpu is not null");

        (obj.class as *mut qemu_sys::CPUClass)
            .as_mut()
            .expect("class is not null")
    };
    let tcg_ops = unsafe {
        (cc.tcg_ops as *mut qemu_sys::TCGCPUOps)
            .as_mut()
            .expect("tcg_ops is not null")
    };

    let tcg_ops_ptr = unsafe {
        // save orig do_interrupt
        assert!(DO_INTERRUPT.is_none());
        DO_INTERRUPT = tcg_ops.do_interrupt;

        // copy vtable to rw memory page
        assert!(TCG_OPS.is_none());
        TCG_OPS = Some(*tcg_ops);
        TCG_OPS.as_mut().unwrap()
    };

    // override do_interrupt
    tcg_ops_ptr.do_interrupt = Some(do_interrupt_hook);

    // set new vtable
    cc.tcg_ops = tcg_ops_ptr;
}
