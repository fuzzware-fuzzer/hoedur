use std::{
    panic, process,
    sync::atomic::{AtomicBool, Ordering},
};

use anyhow::{Context, Result};
use backtrace::Backtrace;
use signal_hook::consts::SIGABRT;

use crate::{hook::QEMU_CALLBACK, qcontrol};

static SIGABORT: AtomicBool = AtomicBool::new(false);

fn abort_hook() {
    if SIGABORT.swap(true, Ordering::Relaxed) {
        log::error!("abort hook called twice, skipping");
        return;
    }

    // dump QEMU state
    log::info!(target: "panic::debug_info", "{:#x?}", qcontrol::cpu());
    #[cfg(feature = "arm")]
    log::info!(target: "panic::debug_info", "{:#x?}", qcontrol().board());

    // dump emulator state
    if let Err(err) = unsafe {
        QEMU_CALLBACK
            .get()
            .context("QEMU hook missing")
            .and_then(|qemu_hook| {
                qemu_hook
                    .as_ptr()
                    .as_mut()
                    .context("Failed to forcefully borrow QEMU hooks")
            })
    }
    .and_then(|hooks| hooks.on_abort().context("Failed to call on_abort hook"))
    {
        log::error!("{:?}", err);
        log::error!("ʕノ•ᴥ•ʔノ ︵ ┻━┻ well... at least we tried to help debug this abort");
    }

    // dump CPU registers
    for register in crate::Register::printable() {
        log::info!(target: "panic::debug_info", "{:<4} = {:08x?}", register, qcontrol().register(register));
    }

    // dump current exception
    log::info!(target: "panic::debug_info", "exception = {:?}", qcontrol().exception());
    #[cfg(feature = "arm")]
    log::info!(target: "panic::debug_info", "nvic exception = {:?}", qcontrol().nvic_exception());

    log::error!(
        "Ladies and gentlemen, this is your captain speaking. We have a small problem. This process is about to crash. We did our best to collect debug information. I trust you are not in too much distress."
    );
}

pub(super) fn register_hooks() -> Result<()> {
    // add signal handler to catch QEMU abort
    let panic_action = || {
        log::error!("received SIGABRT");
        abort_hook();
        log::error!(target: "panic::debug_info", "backtrace:\n{:?}", Backtrace::new());
    };
    unsafe {
        signal_hook::low_level::register(SIGABRT, panic_action)?;
    }

    // add panic hook with added information
    let panic_hook = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        abort_hook();
        panic_hook(info);
        process::exit(-1);
    }));

    Ok(())
}
