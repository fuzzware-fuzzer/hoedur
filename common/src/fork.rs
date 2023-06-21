use std::{
    panic::{self, RefUnwindSafe},
    process,
};

use anyhow::{bail, Context, Result};
use nix::{
    sys::wait::{waitpid, WaitStatus},
    unistd::{fork, ForkResult},
};

pub fn run_as_fork<F: Fn() -> Result<T> + RefUnwindSafe, T>(function: F) -> Result<()> {
    match unsafe { fork() }.context("fork process")? {
        ForkResult::Child => {
            let result = panic::catch_unwind(|| function().context("running child function"));

            // log errror
            match result.as_ref() {
                Err(e) => {
                    log::error!("child function failed: {:?}", e);
                }
                Ok(Err(e)) => {
                    log::error!("child function paniced: {:?}", e);
                }
                Ok(Ok(_)) => {}
            }

            process::exit(match result {
                Err(_) | Ok(Err(_)) => 1,
                Ok(Ok(_)) => 0,
            });
        }
        ForkResult::Parent { child } => {
            match waitpid(Some(child), None).context("wait for child")? {
                WaitStatus::Exited(_, status) => {
                    if status != 0 {
                        bail!("failed with status: {}", status);
                    }
                }
                WaitStatus::Signaled(_, signal, _) => {
                    bail!("failed with signal: {:?}", signal);
                }
                _ => unreachable!(),
            }
        }
    }

    Ok(())
}
