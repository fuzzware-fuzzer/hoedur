use std::{
    fmt::{self, Debug},
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
    sync::{atomic::Ordering, Arc},
};

use anyhow::{Context, Result};
use common::{fs::encoder, FxHashMap, FxHashSet};
use frametracer::{
    symbolizer::Symbolizer, Access, AccessTarget, AccessType, BasicBlock, Instruction, Run,
    TraceEvent,
};
use itertools::Itertools;
use modeling::{hardware::Input, mmio::AccessContext, mmio_model::ReadSize};
use parking_lot::Mutex;
use qemu_rs::{memory::MemoryType, Address, Exception, USize};
use zstd::stream::AutoFinishEncoder;

use crate::{
    hooks::{
        custom::{Bug, HookRuntime, BUGS, STOP},
        debug::DebugHook,
    },
    StopReason,
};

use super::{EmulatorData, ExitHook};

pub(crate) fn ra() -> Address {
    use qemu_rs::{qcontrol, Register};

    #[cfg(feature = "arm")]
    // ARM lr has thumb-bit set, this is PITA for frame recovery - just remove it
    let ra = qcontrol().register(Register::LR) & !(1 as Address);

    ra
}

#[derive(Debug)]
pub enum CustomHook {
    File(PathBuf),
    Script(PathBuf, String),
}

pub(crate) struct EmulatorDebugData {
    enabled: bool,
    trace: bool,
    trace_file: Option<AutoFinishEncoder<'static, BufWriter<File>>>,
    coverage: Option<FxHashSet<Address>>,
    exit_hooks: FxHashMap<Address, Arc<ExitHook>>,
    debug_hooks: FxHashMap<Address, Arc<DebugHook>>,
    custom_hooks: Option<HookRuntime>,
    output_buffer: String,
}

#[derive(Debug, Clone)]
pub struct EmulatorDebugSnapshot {
    output_buffer: String,
}

impl fmt::Debug for EmulatorDebugData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmulatorDebugData")
            .field("enabled", &self.enabled)
            .field("trace", &self.trace)
            .field("trace_file", &self.trace_file.is_some())
            .field("coverage", &self.coverage)
            .field("exit_hooks", &self.exit_hooks)
            .field("debug_hooks", &self.debug_hooks)
            .field("custom_hooks", &self.custom_hooks)
            .field("output_buffer", &self.output_buffer)
            .finish()
    }
}

impl EmulatorDebugData {
    pub(crate) fn new(
        enabled: bool,
        trace: bool,
        coverage: bool,
        symbolizer: Symbolizer,
        exit_hooks: Vec<ExitHook>,
        debug_hooks: Vec<DebugHook>,
        custom_hooks: Vec<CustomHook>,
        trace_file: Option<PathBuf>,
    ) -> Result<Self> {
        // trace file
        let trace_file = if let Some(trace_file) = trace_file {
            Some(encoder(&trace_file)?)
        } else {
            None
        };

        // collect exit hook names
        let exit_hooks = exit_hooks
            .into_iter()
            .map(Arc::new)
            .map(|hook| {
                // resolve hook target
                hook.target()
                    .resolve(&symbolizer)
                    .context("Failed to resolve exit hook addresses")
                    .map(|addresses| {
                        log::info!(
                            "Exit hook {:?} at {:08x?}",
                            hook.name().unwrap_or("<unknown>"),
                            addresses
                        );

                        addresses
                            .into_iter()
                            .map(|address| (address, hook.clone()))
                            .collect::<Vec<_>>()
                    })
            })
            .flatten_ok()
            .collect::<Result<_>>()?;

        // collect debug hooks
        let debug_hooks = debug_hooks
            .into_iter()
            .map(Arc::new)
            .map(|hook| {
                // deprecated warning
                if hook.is_deprecated() {
                    log::warn!("Deprecated debug hook used: {:?}", hook);
                }

                // resolve hook target
                hook.target()
                    .resolve(&symbolizer)
                    .context("Failed to resolve debug hook addresses")
                    .map(|addresses| {
                        if enabled {
                            log::info!(
                                "Debug hook {:?} at {:08x?}",
                                hook.name().unwrap_or("<unknown>"),
                                addresses
                            );
                        }

                        addresses
                            .into_iter()
                            .map(|address| (address, hook.clone()))
                            .collect::<Vec<_>>()
                    })
            })
            .flatten_ok()
            .collect::<Result<_>>()?;

        // shareable symbolizer
        let symbolizer = Arc::new(Mutex::new(symbolizer));

        // create custom hook runtime
        let custom_hooks = if !custom_hooks.is_empty() {
            Some(HookRuntime::new(
                enabled,
                trace,
                &custom_hooks,
                symbolizer.clone(),
            )?)
        } else {
            None
        };

        Ok(Self {
            enabled,
            trace,
            trace_file,
            coverage: coverage.then(FxHashSet::default),
            exit_hooks,
            debug_hooks,
            custom_hooks,
            output_buffer: String::new(),
        })
    }

    pub(crate) fn on_init(&mut self) -> Result<()> {
        // call custom hooks
        if let Some(runtime) = &mut self.custom_hooks {
            runtime.on_init().context("call custom on_init hook")?;
        }

        Ok(())
    }

    pub(crate) fn prepare_run(&mut self, id: usize) -> Result<()> {
        if !self.enabled() {
            return Ok(());
        }

        // call custom hooks
        if let Some(runtime) = &mut self.custom_hooks {
            runtime
                .on_prepare_run()
                .context("call custom prepare_run hook")?;
        }

        self.write_event(TraceEvent::Run(Run { id }))
    }

    pub(crate) fn post_run(&mut self) -> Result<Option<Vec<Bug>>> {
        if !self.enabled() {
            return Ok(None);
        }

        // call custom hooks
        if let Some(runtime) = &mut self.custom_hooks {
            runtime.on_post_run().context("call custom post_run hook")?;
        }

        // end frame trace
        self.write_event(TraceEvent::Stop)?;
        self.flush_trace()?;

        // print output buffer
        if !self.output_buffer.is_empty() {
            log::info!("[output] {}", self.output_buffer);
        }

        // collect input bugs (set by hook scripts)
        Ok(BUGS.lock().take())
    }

    fn flush_trace(&mut self) -> Result<()> {
        // flush trace file
        if let Some(trace_file) = &mut self.trace_file {
            trace_file.flush().context("Failed to flush trace file")?;
        }

        Ok(())
    }

    pub(crate) fn finish_trace(&mut self) -> Result<()> {
        self.flush_trace()?;

        // on abort we want to make sure everything makes it into the trace file
        // we therefore close the file to force zstd to finish
        let _ = self.trace_file.take();

        Ok(())
    }

    fn write_event(&mut self, event: TraceEvent) -> Result<()> {
        if let Some(trace_file) = &mut self.trace_file {
            event
                .write_to(trace_file)
                .context("Failed to serialize trace event")?;
        }

        if let Some(coverage) = &mut self.coverage {
            if let TraceEvent::BasicBlock(bb) = event {
                coverage.insert(bb.pc);
            }
        }

        Ok(())
    }

    fn print_output(&mut self, output: String) {
        log::debug!("print_output(output = {:?})", output);

        // replace strange newline variations and add output to buffer
        self.output_buffer += &output
            .replace("\r\n", "\n")
            .replace("\n\r", "\n")
            .replace('\r', "\n");
        log::debug!("self.output_buffer = {:?}", self.output_buffer);

        if self.output_buffer.contains('\n') {
            let mut lines: Vec<_> = self.output_buffer.lines().collect();

            // buffer may not end with newline => keep remaining line part
            let remaining = if self.output_buffer.ends_with('\n') {
                None
            } else {
                lines.pop()
            };

            // print lines
            for line in lines {
                log::info!("[output] {}", line);
            }

            self.output_buffer = remaining.unwrap_or("").into();
        }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn trace_mode(&self) -> bool {
        self.trace
    }

    pub(crate) fn debug_hooks(&self) -> Option<Vec<u32>> {
        self.enabled()
            .then(|| self.debug_hooks.keys().copied().collect_vec())
    }

    pub(crate) fn take_coverage(&mut self) -> Option<FxHashSet<Address>> {
        if self.coverage.is_some() {
            self.coverage.replace(FxHashSet::default())
        } else {
            None
        }
    }

    pub fn snapshot_create(&self) -> EmulatorDebugSnapshot {
        EmulatorDebugSnapshot {
            output_buffer: self.output_buffer.clone(),
        }
    }

    pub fn snapshot_restore(&mut self, snapshot: &EmulatorDebugSnapshot) {
        self.output_buffer = snapshot.output_buffer.clone();
    }
}

impl<I: Input + Debug> EmulatorData<I> {
    pub(crate) fn check_stop_conditions_debug(&mut self, mmio: bool) -> Result<()> {
        // stop from custom debug hook
        if self.debug.enabled() && STOP.swap(false, Ordering::Relaxed) {
            log::debug!("stop requested from custom hook script");
            if mmio {
                self.create_mmio_rewound()?;
            }

            self.stop(StopReason::Script);
        }

        Ok(())
    }

    pub(crate) fn on_basic_block_debug(&mut self, pc: Address) -> Result<()> {
        if self.debug.enabled() {
            // call custom hooks
            if let Some(runtime) = &mut self.debug.custom_hooks {
                runtime
                    .on_basic_block(pc)
                    .context("call custom basic block hook")?;
            }

            // add basic block to trace
            self.debug
                .write_event(TraceEvent::BasicBlock(BasicBlock { pc, ra: ra() }))
                .context("trace basic block")
        } else {
            Ok(())
        }
    }

    pub(crate) fn on_instruction(&mut self, pc: Address) -> Result<()> {
        if self.debug.enabled() {
            // call custom hooks
            if let Some(runtime) = &mut self.debug.custom_hooks {
                runtime
                    .on_instruction(pc)
                    .context("call custom instruction hook")?;
            }

            // add basic block to trace
            self.debug
                .write_event(TraceEvent::Instruction(Instruction { pc }))
                .context("trace instruction")
        } else {
            Ok(())
        }
    }

    pub(crate) fn on_interrupt_trigger_debug(&mut self, pc: Address) -> Result<()> {
        if !self.debug.enabled() {
            return Ok(());
        } else {
            log::debug!("custom interrupt trigger hit at {pc:#x?}");
        }

        // TODO: call custom hooks?

        Ok(())
    }

    pub(crate) fn on_debug(&mut self, pc: Address) -> Result<()> {
        if let Some(hook) = self.debug.debug_hooks.get(&pc) {
            log::debug!(
                "Hit {:?} debug hook at {:#x?} : {:?}",
                hook,
                pc,
                hook.name()
            );
            match hook.execute() {
                Ok(None) => {}
                Ok(Some(string)) => self.debug.print_output(string),
                Err(e) => log::warn!("Debug hook failed: {:?}", e),
            }
        }

        // call custom hooks
        if let Some(runtime) = &mut self.debug.custom_hooks {
            runtime
                .on_basic_block(pc)
                .context("call custom basic block hook")?;
        }

        Ok(())
    }

    pub(crate) fn on_exit_debug(&mut self, pc: Address) -> Result<()> {
        if !self.debug.enabled() {
            return Ok(());
        } else {
            log::debug!("exit hook hit at basic block {:#x?}", pc);
        }

        if let Some(name) = self.debug.exit_hooks.get(&pc) {
            log::debug!("Hit exit hook at {:#x?} : {:?}", pc, name);
        } else {
            log::error!("Unknown exit hook at {:#x?}", pc);
        }

        // call custom hooks
        if let Some(runtime) = &mut self.debug.custom_hooks {
            runtime.on_exit_hook(pc).context("call custom exit hook")?;
        }

        Ok(())

        // TODO: should there be an `Exit(pc)` event in the trace?
        // self.trace_basic_block(basic_block(pc)?)
    }

    pub(crate) fn on_exception_debug(&mut self, pc: Address, exception: Exception) -> Result<()> {
        log::debug!("exception {} at {:#x?}", exception, pc);
        if !self.debug.enabled() {
            return Ok(());
        }

        // call custom hooks
        if let Some(runtime) = &mut self.debug.custom_hooks {
            runtime
                .on_interrupt(pc, exception)
                .context("call custom IRQ hook")?;
        }

        // trace exception
        self.debug
            .write_event(TraceEvent::Exception(frametracer::Exception {
                pc,
                exception: exception.num(),
            }))
            .context("trace IRQ")
    }

    pub(crate) fn on_exception_exit_debug(&mut self) -> Result<()> {
        log::trace!("exception exit");
        if !self.debug.enabled() {
            return Ok(());
        }

        // trace exception exit
        self.debug
            .write_event(TraceEvent::ExceptionExit)
            .context("trace IRQ exit")
    }

    pub(crate) fn on_task_switch_debug(&mut self, previous: Address, next: Address) -> Result<()> {
        log::debug!("task switch {:08x} -> {:08x}", previous, next);
        if !self.debug.enabled() {
            return Ok(());
        }

        // trace task switch
        self.debug
            .write_event(TraceEvent::TaskSwitch(frametracer::TaskSwitch {
                previous,
                next,
            }))
            .context("trace task switch")
    }

    pub(crate) fn on_access_debug(
        &mut self,
        target: AccessTarget,
        access_type: AccessType,
        context: &AccessContext,
        data: USize,
        size: ReadSize,
    ) -> Result<()> {
        log::trace!(
            "{target:?} {access_type:?}: {context:08x?}, data = {data:08x?}, size = {size:?}"
        );
        if !self.debug.enabled() {
            return Ok(());
        }

        // call custom hooks
        if let Some(runtime) = &mut self.debug.custom_hooks {
            let memory_type = match target {
                AccessTarget::Rom => MemoryType::Rom,
                AccessTarget::Ram => MemoryType::Ram,
                AccessTarget::Mmio => MemoryType::Mmio,
                AccessTarget::Stack => MemoryType::Ram,
            };
            runtime
                .on_memory_access(
                    memory_type,
                    access_type,
                    context.pc(),
                    context.mmio().addr(),
                    data,
                    size as u8,
                )
                .context("call custom MMIO hook")?;
        }

        // add access to trace
        self.debug
            .write_event(TraceEvent::Access(Access {
                target,
                access_type,
                pc: context.pc(),
                address: context.mmio().addr(),
                value: data,
                size: size as u8,
            }))
            .context("trace memory/MMIO access")
    }
}
