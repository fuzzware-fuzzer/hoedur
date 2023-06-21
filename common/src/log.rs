use std::{panic, path::Path, thread};

use anyhow::{Context, Result};
use backtrace::Backtrace;

pub const LOG_INFO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/log/info.yml");
pub const LOG_DEBUG: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/log/debug.yml");
pub const LOG_TRACE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/log/trace.yml");
pub const LOG_TESTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/log/tests.yml");

pub fn init_log(log_config: &Path) -> Result<()> {
    set_panic_log_hook();
    log4rs::init_file(log_config, Default::default()).with_context(|| {
        format!(
            "Failed to initialize logger with config from {:?}",
            &log_config
        )
    })
}

fn set_panic_log_hook() {
    panic::set_hook(Box::new(move |info| {
        let thread = thread::current();
        let thread = thread.name().unwrap_or("<unnamed>");

        let msg = match info.payload().downcast_ref::<&'static str>() {
            Some(s) => *s,
            None => match info.payload().downcast_ref::<String>() {
                Some(s) => &**s,
                None => "Box<Any>",
            },
        };

        match info.location() {
            Some(location) => {
                log::error!(
                    target: "panic", "thread '{}' panicked at '{}': {}:{}",
                    thread,
                    msg,
                    location.file(),
                    location.line()
                );
            }
            None => log::error!(
                target: "panic",
                "thread '{}' panicked at '{}'",
                thread,
                msg
            ),
        }

        log::error!(target: "panic::debug_info", "{:?}", Backtrace::default());
    }));
}
