use crate::Exception;

static mut INTERRUPT: Vec<Exception> = vec![];

pub fn request_interrupt_injection(interrupt: Exception) {
    log::trace!("request_interrupt_injection(interrupt = {:?})", interrupt);

    unsafe {
        INTERRUPT.push(interrupt);
    }
}

pub(crate) fn inject_interrupt() -> bool {
    while let Some(interrupt) = unsafe { INTERRUPT.pop() } {
        let cpu = crate::qcontrol::cpu_mut();

        // enable cpu io
        // this should be safe as we are at the start of an execution block and manually set the PC
        let can_do_io = cpu.parent_obj.can_do_io;
        cpu.parent_obj.can_do_io = 1;

        pend_interrupt(interrupt);

        // kick cpu after interrupt injection
        cpu.parent_obj.halted = 0;

        // restore cpu io state
        cpu.parent_obj.can_do_io = can_do_io;
    }

    false
}

fn pend_interrupt(interrupt: Exception) {
    log::trace!("pend_interrupt(interrupt = {:?})", interrupt);

    #[cfg(feature = "arm")]
    {
        // NVIC needs special care
        if let Some(exception) = interrupt.as_nvic() {
            exception.pend();
            return;
        }

        if let Some(exception) = interrupt.as_cpu() {
            exception.pend();
            return;
        }

        unreachable!("invalid interrupt");
    }

    #[cfg(not(feature = "arm"))]
    interrupt.pend();
}
