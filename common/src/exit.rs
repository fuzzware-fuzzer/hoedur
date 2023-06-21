use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{bail, Result};

pub static EXIT: AtomicBool = AtomicBool::new(false);
pub static TERM: AtomicBool = AtomicBool::new(false);

/// clean exit on signals
pub fn signal_exit_point() -> Result<()> {
    if EXIT.load(Ordering::Relaxed) {
        if TERM.load(Ordering::Relaxed) {
            ::log::warn!("forced QEMU stop");
        }
        bail!("stopping after term signal");
    }

    Ok(())
}

/// terminate on signals
pub fn signal_term_point() -> Result<()> {
    if TERM.load(Ordering::Relaxed) {
        bail!("forced QEMU stop, stopping after term signal");
    }

    Ok(())
}
