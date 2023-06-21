use std::{hash::Hash, path::PathBuf};

use qemu_rs::{Address, Exception};
use serde::Deserialize;

use crate::fuzzware;

pub use indexmap::IndexMap;

const EXCEPTION_NO_EXTERNAL_START: i32 = 0x10;

#[repr(transparent)]
#[derive(Debug, Default, Clone, Copy, Deserialize)]
pub struct DisabledInterrupt(i32);

impl From<i32> for DisabledInterrupt {
    fn from(val: i32) -> Self {
        Self(val)
    }
}

impl Into<Exception> for DisabledInterrupt {
    fn into(self) -> Exception {
        Exception::from(EXCEPTION_NO_EXTERNAL_START + self.0)
    }
}

#[derive(Debug, Deserialize)]
pub struct ConfigInclude {
    pub include: Option<Vec<PathBuf>>,
}

#[derive(Debug, Default, Deserialize)]
pub struct FuzzwareConfig {
    pub memory_map: Option<IndexMap<String, MemoryMap>>,
    pub entry_point: Option<Address>,
    pub initial_sp: Option<Address>,
    pub symbols: Option<IndexMap<Address, String>>,
    pub exit_at: Option<IndexMap<String, Option<Target>>>,
    pub handlers: Option<IndexMap<String, Option<HandlerWrapper>>>,
    pub interrupt_triggers: Option<IndexMap<String, InterruptTrigger>>,
    pub boot: Option<Boot>,
    pub limits: Option<Limits>,
    pub mmio_models: Option<fuzzware::mmio_models::MmioModels>,
    pub use_exit_at: Option<bool>,
    pub use_nvic: Option<bool>,
    pub use_systick: Option<bool>,
    pub nvic: Option<Nvic>,
    pub timers: Option<IndexMap<Address, Timer>>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum HandlerWrapper {
    Shorthand(String),
    Handler(Handler),
}

#[derive(Debug, Deserialize)]
pub struct Handler {
    #[serde(rename = "addr")]
    pub address: Option<Target>,
    #[serde(default = "default_do_return")]
    pub do_return: bool,
    pub handler: Option<String>,
}

fn default_do_return() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct InterruptTrigger {
    #[serde(rename = "every_nth_tick")]
    pub interval: Option<usize>,
    #[serde(flatten)]
    pub mode: InterruptMode,
    #[serde(rename = "addr")]
    pub address: Option<Target>,
    pub num_pends: Option<usize>,
    pub num_skips: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Target {
    Address(Address),
    Symbol(String),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum InterruptMode {
    Fixed { irq: Exception },
    FuzzMode { fuzz_mode: FuzzMode },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzMode {
    Fuzzed,
    RoundRobin,
}

#[derive(Debug, Deserialize)]
pub struct MemoryMap {
    #[serde(rename = "base_addr")]
    pub address: Address,
    pub size: Address,
    pub permissions: String,
    pub file: Option<String>,
    pub overlay: Option<bool>,
    pub is_entry: Option<bool>,
    pub ivt_offset: Option<Address>,
    pub file_offset: Option<Address>,
    pub load_offset: Option<Address>,
}

#[derive(Debug, Deserialize)]
pub struct Boot {
    pub required: Option<Vec<Target>>,
    pub avoid: Option<Vec<Target>>,
    pub target: Option<Target>,
}

#[derive(Debug, Deserialize)]
pub struct Limits {
    pub translation_blocks: Option<usize>,
    pub fuzz_consumption_timeout: Option<usize>,
    pub interrupts: Option<usize>,
    pub trace_events: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct Nvic {
    pub vtor: Option<Address>,
    pub num_vecs: Option<u16>,
    pub disabled_irqs: Option<Vec<DisabledInterrupt>>,
}

#[derive(Debug, Deserialize)]
pub struct Timer {
    pub reload_val: usize,
    pub handler: String,
    pub start_at: Option<Address>,
}

impl FuzzwareConfig {
    pub fn merge(&mut self, config: FuzzwareConfig) {
        merge(&mut self.memory_map, config.memory_map);
        set(&mut self.entry_point, config.entry_point);
        set(&mut self.initial_sp, config.initial_sp);
        merge(&mut self.symbols, config.symbols);
        merge(&mut self.exit_at, config.exit_at);
        merge(&mut self.handlers, config.handlers);
        merge(&mut self.interrupt_triggers, config.interrupt_triggers);
        set(&mut self.boot, config.boot);
        set(&mut self.limits, config.limits);
        set(&mut self.mmio_models, config.mmio_models);
        set(&mut self.use_exit_at, config.use_exit_at);
        set(&mut self.use_nvic, config.use_nvic);
        set(&mut self.use_systick, config.use_systick);
        set(&mut self.nvic, config.nvic);
        merge(&mut self.timers, config.timers);
    }
}

pub fn merge<K: Eq + Hash, V>(this: &mut Option<IndexMap<K, V>>, that: Option<IndexMap<K, V>>) {
    if let Some(that) = that {
        match this {
            Some(this) => {
                for (key, value) in that.into_iter() {
                    let old = this.insert(key, value);

                    if old.is_some() {
                        log::warn!("include replaced old value");
                    }
                }
            }
            None => *this = Some(that),
        }
    }
}

pub fn set<T>(this: &mut Option<T>, that: Option<T>) {
    if let Some(that) = that {
        let old = this.replace(that);

        if old.is_some() {
            log::warn!("include replaced old value");
        }
    }
}
