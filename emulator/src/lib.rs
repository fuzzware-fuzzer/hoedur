use std::{
    cell::{Ref, RefCell},
    convert::TryFrom,
    fmt::{self, Debug},
    num::NonZeroUsize,
    path::PathBuf,
    rc::Rc,
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
    usize,
};

use anyhow::{Context, Result};
use arch::{ArchEmulator, ArchEmulatorSnapshot};
use common::{
    config::emulator::FIX_EXCEPTION_EDGE, exit::EXIT, file_storage::FileStorage, fs::bufwriter,
    FxHashSet,
};
use debug::{CustomHook, EmulatorDebugSnapshot};
use enum_index_derive::EnumIndex;
use frametracer::{
    symbolizer::{Object, Symbolizer},
    AccessTarget, AccessType,
};
use hooks::exit::ExitHook;
use interrupt::{EmulatorInterruptConfig, EmulatorInterruptConfigSnapshot, TargetInterruptConfig};
use itertools::Itertools;
use modeling::{
    hardware::{Hardware, HardwareResult, HardwareSnapshot, Input},
    mmio::{AccessContext, Mmio},
    mmio_model::ReadSize,
    modeling::Modeling,
};
use qemu_rs::{
    board::Board, init_qemu, memory::MemoryMap, qcontrol, CpuModel, Event, Exception, MemoryBlock,
    MmioRewound, QemuCallback, QemuStopReason, Snapshot, USize,
};
use serde::{Deserialize, Serialize};
use variant_count::VariantCount;

pub use qemu_rs::Address;

mod arch;
mod counts;
mod debug;
mod fuzzware;
mod hooks;
mod interrupt;
mod limits;

pub mod archive;

pub mod coverage {
    pub use qemu_rs::coverage::{RawBitmap, RawEntry, HASH_KEY};
}

pub use self::{counts::EmulatorCounts, hooks::custom::Bug, limits::EmulatorLimits};
use self::{debug::EmulatorDebugData, hooks::debug::DebugHook, limits::TargetLimits};

pub type CoverageLog = FxHashSet<Address>;

#[derive(Debug)]
pub struct ExecutionResult<I: Input + Debug> {
    pub counts: EmulatorCounts,
    pub hardware: HardwareResult<I>,
    pub coverage: Option<CoverageLog>,
    pub execution_time: Duration,
    pub stop_reason: StopReason,
    pub bugs: Option<Vec<Bug>>,
}

impl<I: Input + Debug> fmt::Display for ExecutionResult<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x?}", self.stop_reason,)?;

        if let Some(bugs) = &self.bugs {
            if bugs.is_empty() {
                write!(f, ", no bugs")?;
            } else {
                write!(f, ", bugs: {bugs:?}")?;
            }
        }

        write!(
            f,
            ", {} basic blocks executed in {:.3} ms, {} interrupts, read {} ({} input) MMIO values",
            self.counts.basic_block,
            self.execution_time.as_micros() as f64 / 1000.,
            self.counts.interrupt,
            self.counts.mmio_read,
            self.hardware.access_log.len()
        )?;

        if let Some(coverage) = &self.coverage {
            write!(f, ", {} tb coverage", coverage.len())?;
        }

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub enum StopReason {
    LimitReached(Limit),
    InfiniteSleep,
    EndOfInput,
    ExitHook,
    Panic,
    Crash {
        pc: Address,
        ra: Address,
        exception: Exception,
    },
    NonExecutable {
        pc: Address,
    },
    RomWrite {
        pc: Address,
        addr: Address,
    },
    Script,
    Reset,
    Shutdown,
    Abort,
    UserExitRequest,
}

#[derive(
    Debug, PartialEq, Eq, Hash, Clone, Copy, EnumIndex, VariantCount, Serialize, Deserialize,
)]
pub enum Limit {
    BasicBlocks,
    Interrupts,
    MmioRead,
    InputReadOverdue,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RunMode {
    Normal,
    Leaf,
}

#[derive(Debug)]
pub(crate) struct EmulatorData<I: 'static + Input + Debug> {
    arch: ArchEmulator,
    hardware: Hardware<I>,
    counts: EmulatorCounts,
    interrupt: EmulatorInterruptConfig,
    mmio_rewound: Option<MmioRewound>,
    last_input_read: usize,
    interrupt_last_location: Vec<u64>,
    step_size: Option<NonZeroUsize>,
    execution_start: Option<Instant>,
    stop: Option<StopReason>,
    limits: EmulatorLimits,
    input_limits: Option<EmulatorLimits>,
    debug: EmulatorDebugData,
}

impl<I: Input + Debug> EmulatorData<I> {
    fn new(
        cpu: CpuModel,
        board: Board,
        modeling: Modeling,
        limits: EmulatorLimits,
        interrupt: EmulatorInterruptConfig,
        debug: EmulatorDebugData,
    ) -> Self {
        Self {
            arch: ArchEmulator::new(cpu, board),
            hardware: Hardware::new(modeling),
            counts: EmulatorCounts::default(),
            interrupt,
            mmio_rewound: None,
            last_input_read: 0,
            step_size: None,
            interrupt_last_location: vec![],
            execution_start: None,
            stop: None,
            limits,
            input_limits: None,
            debug,
        }
    }

    fn prepare_run(&mut self, input: I) -> Result<()> {
        log::trace!("prepare_run");
        log::debug!("running input {} ...", input.id());

        // verify emulator is in an expected state
        debug_assert!(self.stop.is_none());
        debug_assert!(self.execution_start.is_none());

        // MMIO rewound: cflags
        if let Some(mmio_rewound) = &self.mmio_rewound {
            log::trace!("prepare_run: mmio_rewound = {:x?}", mmio_rewound);
            mmio_rewound.restore();
        }

        // set next basic block hook (single step for rewound)
        self.set_next_basic_block_hook(self.mmio_rewound.is_some());

        self.debug.prepare_run(input.id())?;
        self.hardware.prepare_run(input);
        self.execution_start = Some(Instant::now());

        Ok(())
    }

    fn post_run(
        &mut self,
        qemu_stop_reason: Option<qemu_rs::QemuStopReason>,
    ) -> Result<ExecutionResult<I>> {
        let bugs = self.debug.post_run()?;

        // update counts
        self.update_basic_block_count()?;

        // remove temporary input limits
        self.input_limits.take();

        // consider qemu stop reason when we didn't expect a stop
        let stop_reason = self.stop.take().unwrap_or(match qemu_stop_reason {
            Some(QemuStopReason::Panic) => StopReason::Panic,
            Some(QemuStopReason::Reset) => StopReason::Reset,
            Some(QemuStopReason::Shutdown) => StopReason::Shutdown,
            _ => StopReason::Abort,
        });

        Ok(ExecutionResult {
            counts: self.counts.clone(),
            hardware: self
                .hardware
                .take_result()
                .context("Failed to take hardware result")?,
            coverage: self.debug.take_coverage(),
            execution_time: Instant::now()
                - self
                    .execution_start
                    .take()
                    .context("Missing execution start time")?,
            stop_reason,
            bugs,
        })
    }

    fn stop(&mut self, reason: StopReason) {
        log::debug!("stop(reason = {:x?})", reason);
        self.stop = Some(reason);
        qemu_rs::request_stop();
    }

    fn create_mmio_rewound(&mut self) -> Result<()> {
        self.mmio_rewound = Some(MmioRewound::create());
        Ok(())
    }

    fn update_basic_block_count(&mut self) -> Result<()> {
        self.update_basic_block_count_inner(false)
    }

    fn update_basic_block_count_inner(&mut self, with_stop: bool) -> Result<()> {
        // update basic block count once
        if let Some(step_size) = self.step_size.take() {
            let offset = qemu_rs::get_next_basic_block_hook() as usize;
            let ticks = step_size.get() - offset;

            // check if we hit a stop limit
            let ticks = if with_stop && self.check_stop_conditions(ticks)? {
                // exclude this basic block in ticks
                ticks.saturating_sub(1)
            } else {
                // update step_size
                self.step_size = NonZeroUsize::new(offset);

                // include this basic block in ticks
                ticks
            };

            // update executed basic block count
            self.counts.basic_block = self.counts.basic_block.saturating_add(ticks);

            // update arch specific counts (e.g. SysTick on ARM Cortex-M)
            ArchEmulator::update_basic_block_count(self, ticks);
        }

        Ok(())
    }

    fn offset_limits(&mut self) {
        if let Some(basic_blocks) = &mut self.limits.basic_blocks {
            *basic_blocks += self.counts.basic_block;
        }
        if let Some(interrupts) = &mut self.limits.interrupts {
            *interrupts += self.counts.interrupt;
        }
        if let Some(mmio_read) = &mut self.limits.mmio_read {
            *mmio_read += self.counts.mmio_read;
        }
    }

    fn limits(&self) -> &EmulatorLimits {
        self.input_limits.as_ref().unwrap_or(&self.limits)
    }

    fn set_limits(&mut self, limits: EmulatorLimits) {
        self.input_limits = Some(limits);
    }

    fn check_stop_conditions(&mut self, ticks: usize) -> Result<bool> {
        // basic block limit
        if let Some(limit) = self.limits().basic_blocks {
            if self.counts.basic_block + ticks > limit {
                log::debug!("basic block limit reached");
                assert_eq!(self.counts.basic_block + ticks - 1, limit);
                self.stop(StopReason::LimitReached(Limit::BasicBlocks));
                return Ok(true);
            }
        }

        // basic blocks with input consumption limit
        if let Some(limit) = self.limits().input_read_overdue {
            if self.counts.basic_block + ticks > self.last_input_read + limit {
                log::debug!("input read overdue");
                assert_eq!(
                    self.last_input_read + limit,
                    self.counts.basic_block + ticks - 1
                );
                self.stop(StopReason::LimitReached(Limit::InputReadOverdue));
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn set_next_basic_block_hook(&mut self, single_step: bool) {
        let step_size = if single_step
            // TRACE-MODE: hook every basic block
            || self.debug.trace_mode()
        {
            1
        } else {
            // TODO: improve performance of this
            // maybe use a timer like approach
            [
                // basic block limit - already executed basic blocks
                self.limits()
                    .basic_blocks
                    // basic blocks left + 1 (stop before next basic block)
                    .map(|limit| limit - self.counts.basic_block + 1),
                // input read overdue
                self.limits().input_read_overdue.map(|input_overdue| {
                    input_overdue - (self.counts.basic_block - self.last_input_read) + 1
                }),
                // next interrupt injection
                self.interrupt.next_interval(&self.counts),
                // arch specific (e.g. SysTick)
                ArchEmulator::next_basic_block_hook(self),
            ]
            .iter()
            .copied()
            .flatten()
            .min()
            .expect("some limit is set")
        };

        // update (basic block hook) step size
        self.step_size = NonZeroUsize::new(step_size);

        // set next hook
        qemu_rs::set_next_basic_block_hook(step_size as u64);
    }

    fn handle_exception(&mut self, pc: Address, ra: Address, exception: Exception) -> Result<()> {
        // IRQ count / limit
        self.counts.interrupt += 1;
        if let Some(limit) = self.limits().interrupts {
            if self.counts.interrupt >= limit {
                log::debug!("IRQ limit reached");
                self.stop(StopReason::LimitReached(Limit::Interrupts));
            }
        }

        self.on_exception_debug(pc, exception)?;

        if exception.is_fatal() {
            self.stop(StopReason::Crash { pc, ra, exception });
            log::debug!("fatal exception {} at {:#x?} detected", exception, pc);
        }

        Ok(())
    }

    fn fix_exception_edge(&mut self) {
        // NOTE: can be disabled for debug purposes
        if !FIX_EXCEPTION_EDGE {
            return;
        }

        // save last_location before exception
        self.interrupt_last_location
            .push(qemu_rs::coverage::get_last_location());

        // set static last location for exception
        qemu_rs::coverage::set_last_location(0);
    }

    fn handle_exception_exit(&mut self) -> Result<()> {
        // NOTE: can be disabled for debug purposes
        if FIX_EXCEPTION_EDGE {
            // restore last_location of basic block before exception
            let last_location = self
                .interrupt_last_location
                .pop()
                .context("missing last pc")?;
            qemu_rs::coverage::set_last_location(last_location);
        }

        ArchEmulator::on_exception_exit(self)?;
        self.on_exception_exit_debug()?;

        Ok(())
    }

    fn inject_interrupt(&mut self, force_raise: bool) -> bool {
        log::trace!("inject_interrupt");

        if let Some(irq) =
            self.interrupt
                .next_interrupt(&self.arch, &self.counts, &mut self.hardware, force_raise)
        {
            qemu_rs::request_interrupt_injection(irq);
            true
        } else {
            false
        }
    }

    pub fn snapshot_create(&self) -> Result<EmulatorSnapshot> {
        Ok(EmulatorSnapshot {
            arch: self
                .arch
                .snapshot_create()
                .context("Failed to create arch snapshot")?,
            qemu: Rc::new(qemu_rs::Snapshot::create().context("Failed to create qemu snapshot")?),
            hardware: self.hardware.snapshot_create(),
            interrupt: self.interrupt.snapshot_create(),
            counts: self.counts.clone(),
            mmio_rewound: self.mmio_rewound.clone(),
            last_input_read: self.last_input_read,
            interrupt_last_location: self.interrupt_last_location.clone(),
            step_size: self.step_size,
            debug: self.debug.enabled().then(|| self.debug.snapshot_create()),
        })
    }

    pub fn snapshot_restore(&mut self, snapshot: &EmulatorSnapshot) -> Result<()> {
        let EmulatorSnapshot {
            arch,
            qemu,
            hardware,
            interrupt,
            counts,
            mmio_rewound,
            last_input_read,
            interrupt_last_location,
            step_size,
            debug,
        } = snapshot;

        self.arch
            .snapshot_restore(arch)
            .context("Failed to restore arch snapshot")?;
        self.hardware.snapshot_restore(hardware);
        self.interrupt.snapshot_restore(interrupt);
        self.counts = counts.clone();
        self.mmio_rewound = mmio_rewound.clone();
        self.last_input_read = *last_input_read;
        self.interrupt_last_location = interrupt_last_location.clone();
        self.step_size = *step_size;

        if let Some(debug) = debug {
            self.debug.snapshot_restore(debug);
        }

        qemu.restore().context("Failed to restore qemu snapshot")
    }
}

impl<I: Input + Debug> QemuCallback for EmulatorData<I> {
    fn on_basic_block(&mut self, pc: Address) -> Result<()> {
        debug_assert_eq!(qemu_rs::get_next_basic_block_hook(), 0);
        assert!(self.stop.is_none(), "QEMU did not stop");

        // MMIO rewound: restore last_location, skip basic block
        if let Some(mmio_rewound) = self.mmio_rewound.take() {
            log::trace!("on_basic_block: mmio_rewound = {:x?}", mmio_rewound);
            mmio_rewound.restore();
            self.set_next_basic_block_hook(false);
            // skip rewound basic block
            return Ok(());
        }

        // update basic block count (and may stop execution when limits are reached)
        self.update_basic_block_count_inner(true)?;

        // stop before this basic block
        if self.stop.is_some() {
            return Ok(());
        }

        ArchEmulator::on_basic_block(self, pc)?;

        // inject IRQ
        if let Some(next_irq) = self.interrupt.next_interval(&self.counts) {
            if next_irq == 0 {
                self.inject_interrupt(false);
            }
        }

        // add this basic block to the coverage bitmap
        qemu_rs::coverage::add_basic_block(pc as u64);

        self.on_basic_block_debug(pc)?;
        self.check_stop_conditions_debug(false)?;

        self.set_next_basic_block_hook(false);
        debug_assert!(self.step_size.is_some() || self.stop.is_some());

        Ok(())
    }

    fn on_instruction(&mut self, pc: Address) -> Result<()> {
        Self::on_instruction(self, pc)
    }

    fn on_interrupt_trigger(&mut self, pc: Address) -> Result<()> {
        self.on_interrupt_trigger_debug(pc)?;
        self.update_basic_block_count()?;

        // try to inject a interrupt
        self.inject_interrupt(false);

        Ok(())
    }

    fn on_debug(&mut self, pc: Address) -> Result<()> {
        Self::on_debug(self, pc)
    }

    fn on_exit(&mut self, pc: Address) -> Result<()> {
        self.on_exit_debug(pc)?;

        self.stop(StopReason::ExitHook);

        Ok(())
    }

    fn on_nx(&mut self, pc: Address) -> Result<()> {
        log::debug!(
            "tried to execute non-exectuable memory region at {:#x?}",
            pc
        );
        // TODO: maybe add to trace

        self.stop(StopReason::NonExecutable { pc });

        Ok(())
    }

    fn on_wait_for_interrupt(&mut self, halted: bool) -> Result<()> {
        self.update_basic_block_count()?;

        // skip on stop
        if self.stop.is_some() {
            return Ok(());
        }

        // try to inject a interrupt, if we can't and CPU is halted stop with "infinite-sleep"
        if !self.inject_interrupt(true) && halted {
            log::debug!("infinite sleep detected");
            self.stop(StopReason::InfiniteSleep);
        }

        Ok(())
    }

    fn on_update(&mut self, event: Event) -> Result<()> {
        log::trace!("QEMU update event: {:?}", event);
        ArchEmulator::on_update(self, event)
    }

    fn on_exception(&mut self, exception: Exception) -> Result<bool> {
        ArchEmulator::on_exception(self, exception)
    }

    fn on_read(&mut self, pc: Address, addr: Address, size: u8) -> Result<u64> {
        debug_assert!(self.mmio_rewound.is_none());

        // MMIO read limit
        if let Some(limit) = self.limits().mmio_read {
            if self.counts.mmio_read >= limit {
                log::debug!("MMIO read limit reached");
                self.create_mmio_rewound()?;
                self.stop(StopReason::LimitReached(Limit::MmioRead));
                return Ok(0);
            }
        }

        let context = AccessContext::new(pc, addr);
        let size = ReadSize::try_from(size as u32)?;
        let value = match self.hardware.mmio_read(&context, size) {
            Ok(Some((data, input))) => {
                // update MMIO read count
                self.counts.mmio_read += 1;

                // MMIO read from input file
                if input {
                    // set last input read + update next basic block hook
                    self.update_basic_block_count()?;
                    self.last_input_read = self.counts.basic_block;
                    self.set_next_basic_block_hook(false);
                }

                self.on_access_debug(AccessTarget::Mmio, AccessType::Read, &context, data, size)?;
                self.check_stop_conditions_debug(true)?;

                data as u64
            }
            Ok(None) => {
                // end of input stream
                self.create_mmio_rewound()?;
                self.stop(StopReason::EndOfInput);

                0
            }
            Err(err) if EXIT.load(Ordering::Relaxed) => {
                // swallow fuzzware error when exit request is present
                log::warn!("MMIO read failed during exit request, likely due to signal");
                log::debug!("{:?}", err);
                self.stop(StopReason::UserExitRequest);

                0
            }
            Err(err) => {
                return Err(err.context("MMIO read failed"));
            }
        };

        Ok(value)
    }

    fn on_write(&mut self, pc: Address, addr: Address, data: u64, size: u8) -> Result<()> {
        debug_assert!(self.mmio_rewound.is_none());

        let context = AccessContext::new(pc, addr);
        let size = ReadSize::try_from(size as u32)?;
        self.hardware.mmio_write(&context, data as USize, size);
        self.counts.mmio_write += 1;

        self.on_access_debug(
            AccessTarget::Mmio,
            AccessType::Write,
            &context,
            data as USize,
            size,
        )?;
        self.check_stop_conditions_debug(true)?;

        Ok(())
    }

    fn on_ram_read(&mut self, pc: Address, addr: Address, data: u64, size: u8) -> Result<()> {
        let context = AccessContext::new(pc, addr);
        self.on_access_debug(
            AccessTarget::Ram,
            AccessType::Read,
            &context,
            data as USize,
            ReadSize::try_from(size as u32)?,
        )
    }

    fn on_ram_write(&mut self, pc: Address, addr: Address, data: u64, size: u8) -> Result<()> {
        let context = AccessContext::new(pc, addr);
        self.on_access_debug(
            AccessTarget::Ram,
            AccessType::Write,
            &context,
            data as USize,
            ReadSize::try_from(size as u32)?,
        )
    }

    fn on_rom_read(&mut self, pc: Address, addr: Address, data: u64, size: u8) -> Result<()> {
        let context = AccessContext::new(pc, addr);
        self.on_access_debug(
            AccessTarget::Rom,
            AccessType::Read,
            &context,
            data as USize,
            ReadSize::try_from(size as u32)?,
        )
    }

    fn on_rom_write(&mut self, pc: Address, addr: Address, data: u64, size: u8) -> Result<()> {
        let context = AccessContext::new(pc, addr);
        self.on_access_debug(
            AccessTarget::Rom,
            AccessType::Write,
            &context,
            data as USize,
            ReadSize::try_from(size as u32)?,
        )?;

        // only set ROM-write stop reason once
        if !matches!(self.stop, Some(StopReason::RomWrite { .. })) {
            self.stop(StopReason::RomWrite { pc, addr });
        }

        Ok(())
    }

    fn on_abort(&mut self) -> Result<()> {
        log::info!("QEMU abort / panic, collecting debug info in logfile...");
        log::info!(target: "panic::debug_info", "emulator = {:#x?}", self);

        // dump current input into file
        match self.hardware.take_result() {
            Ok(hardware_result) => {
                let path = PathBuf::from(hardware_result.input.filename());
                log::info!(
                    target: "panic::debug_info",
                    "Writing current input file causing QEMU abort to {:?} ...",
                    path
                );
                hardware_result.input.write_to(&mut bufwriter(&path)?)?;
            }
            Err(err) => log::error!(
                "Failed to take hardware result with current input file: {:?}",
                err
            ),
        }

        // flush open files
        self.debug.finish_trace()?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct Emulator<I: 'static + Input + Debug> {
    emudata: Arc<RefCell<EmulatorData<I>>>,
}

#[derive(Debug, Clone)]
pub struct EmulatorSnapshot {
    arch: ArchEmulatorSnapshot,
    qemu: Rc<Snapshot>,
    hardware: HardwareSnapshot,
    interrupt: EmulatorInterruptConfigSnapshot,
    counts: EmulatorCounts,
    mmio_rewound: Option<MmioRewound>,
    last_input_read: usize,
    interrupt_last_location: Vec<u64>,
    step_size: Option<NonZeroUsize>,
    debug: Option<EmulatorDebugSnapshot>,
}

impl<I: Input + Debug> Drop for Emulator<I> {
    fn drop(&mut self) {
        qemu_rs::drop().expect("Failed to drop QEMU");
    }
}

impl<I: Input + Debug> Emulator<I> {
    pub fn new(
        file_storage: &FileStorage,
        config: EmulatorConfig,
        mut modeling: Modeling,
    ) -> Result<Self> {
        let target = config.target;
        let board = target.board.unwrap_or_default();
        let cpu = target
            .cpu
            .as_deref()
            .map(CpuModel::try_from)
            .unwrap_or_else(|| Ok(CpuModel::default()))
            .context("parse target cpu")?;

        if let Some(models) = target.mmio_models {
            modeling
                .append_models(models)
                .context("Failed append models")?;
        }

        // create symbolizer
        let objects = target
            .symbols
            .unwrap_or_default()
            .iter()
            .map(|path| {
                file_storage
                    .get(path)
                    .with_context(|| {
                        format!("Failed to get symbols file {:?} from file storage", path)
                    })
                    .and_then(|bytes| {
                        Object::from_bytes(bytes)
                            .with_context(|| format!("Failed to parse object file {:?}", path))
                    })
            })
            .collect::<Result<Vec<_>>>()
            .context("Failed to load symbols")?;
        let symbolizer = Symbolizer::new(objects);

        // custom interrupt trigger
        let interrupt: EmulatorInterruptConfig = target.interrupt.unwrap_or_default().into();
        let mut interrupt_trigger = interrupt.custom_trigger(&symbolizer)?;
        interrupt_trigger.sort();
        interrupt_trigger.dedup();

        // exit hooks
        let exit_hooks = target.exit_hooks.unwrap_or_default();
        let mut exit_hooks_pc = exit_hooks
            .iter()
            .map(|hook| hook.target().resolve(&symbolizer))
            .flatten_ok()
            .collect::<Result<Vec<_>>>()
            .context("Failed to resolve exit hook addresses")?;
        exit_hooks_pc.sort();
        exit_hooks_pc.dedup();

        // custom debug hooks (scripts)
        let debug = config.debug;
        let custom_hooks =
            debug
                .hooks
                .into_iter()
                .map(CustomHook::File)
                .chain(target.script.into_iter().map(|script| {
                    CustomHook::Script(file_storage.target_config().to_owned(), script)
                }))
                .collect();

        // emulator debug related data
        let debug_data = EmulatorDebugData::new(
            debug.enabled,
            debug.trace,
            debug.coverage,
            symbolizer,
            exit_hooks,
            target.debug_hooks.unwrap_or_default(),
            custom_hooks,
            debug.trace_file,
        )?;

        // callback handler
        let emudata = Arc::new(RefCell::new(EmulatorData::new(
            cpu,
            board.clone(),
            modeling,
            target.limits.unwrap_or_default().into(),
            interrupt,
            debug_data,
        )));

        // hook first basic block
        qemu_rs::set_next_basic_block_hook(1);

        // init qemu
        init_qemu(
            cpu,
            board,
            file_storage,
            emudata.clone(),
            target.memory_maps,
            interrupt_trigger,
            exit_hooks_pc,
            emudata.borrow().debug.debug_hooks(),
            emudata.borrow().debug.trace_mode(),
        )
        .context("init qemu")?;

        // call on_init hook
        emudata.borrow_mut().debug.on_init()?;

        // create emulator
        Ok(Self { emudata })
    }

    pub fn get_coverage_bitmap(&self) -> &coverage::RawBitmap {
        qemu_rs::coverage::get_coverage_bitmap()
    }

    pub fn memory_blocks(&self) -> impl Iterator<Item = MemoryBlock> {
        qcontrol().memory_blocks()
    }

    pub fn snapshot_create(&mut self) -> Result<EmulatorSnapshot> {
        log::debug!("snapshot create");
        self.emudata.borrow_mut().snapshot_create()
    }

    pub fn snapshot_restore(&mut self, snapshot: &EmulatorSnapshot) {
        log::debug!("snapshot restore");
        self.emudata
            .borrow_mut()
            .snapshot_restore(snapshot)
            .unwrap();
    }

    pub fn set_next_input_limits(&mut self, limits: EmulatorLimits) {
        self.emudata.borrow_mut().set_limits(limits)
    }

    pub fn counts(&mut self) -> EmulatorCounts {
        self.emudata.borrow_mut().counts.clone()
    }

    pub fn offset_limits(&mut self) {
        self.emudata.borrow_mut().offset_limits()
    }

    pub fn hardware(&self) -> Ref<'_, Hardware<I>> {
        Ref::map(self.emudata.borrow(), |emudata| &emudata.hardware)
    }

    pub fn run(&mut self, input: I, mode: RunMode) -> Result<ExecutionResult<I>> {
        self.emudata
            .borrow_mut()
            .prepare_run(input)
            .context("prepare run")?;

        let stop_reason = match mode {
            RunMode::Normal | RunMode::Leaf => qemu_rs::run()?,
        };

        let result = self
            .emudata
            .borrow_mut()
            .post_run(stop_reason)
            .context("post run");
        log::trace!("result = {:#x?}", result);

        result
    }
}

#[derive(Debug)]
pub struct EmulatorConfig {
    target: EmulatorTargetConfig,
    debug: EmulatorDebugConfig,
}

impl EmulatorConfig {
    pub fn read_from(file_storage: &mut FileStorage, debug: EmulatorDebugConfig) -> Result<Self> {
        // load target config
        let target = EmulatorTargetConfig::read_from(file_storage).with_context(|| {
            format!(
                "Failed to load emulator target config from {:?}",
                file_storage.target_config()
            )
        })?;
        log::debug!("target = {:#x?}", target);

        Ok(Self { target, debug })
    }
}

#[derive(Debug, Default)]
pub struct EmulatorDebugConfig {
    enabled: bool,
    trace: bool,
    trace_file: Option<PathBuf>,
    coverage: bool,
    hooks: Vec<PathBuf>,
}

impl EmulatorDebugConfig {
    pub fn new(
        enabled: bool,
        trace: bool,
        trace_file: Option<PathBuf>,
        coverage: bool,
        hooks: Vec<PathBuf>,
    ) -> Self {
        Self {
            enabled,
            trace,
            trace_file,
            coverage,
            hooks,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmulatorTargetConfig {
    cpu: Option<String>,
    board: Option<Board>,
    limits: Option<TargetLimits>,
    interrupt: Option<TargetInterruptConfig>,
    memory_maps: Vec<MemoryMap>,
    mmio_models: Option<Vec<Mmio>>,
    exit_hooks: Option<Vec<ExitHook>>,
    debug_hooks: Option<Vec<DebugHook>>,
    symbols: Option<Vec<PathBuf>>,
    script: Option<String>,
}

impl EmulatorTargetConfig {
    pub fn read_from(file_storage: &mut FileStorage) -> Result<Self> {
        // target config
        let path = file_storage.target_config().to_owned();

        // read/parse config
        let content = file_storage
            .get(&path)
            .with_context(|| format!("Failed to read emulator config file {path:?}"))?;
        let mut config: Self = serde_yaml::from_slice(content)
            .with_context(|| format!("Failed to parse emulator config file {path:?}"))?;

        // resolve relative to absolute MemoryMap data and preload files
        config
            .memory_maps
            .iter_mut()
            .try_for_each(|memmap| memmap.prepare_file(file_storage))
            .context("Failed to prepare memory map files")?;

        // preload debug symbols
        config
            .symbols
            .iter()
            .flatten()
            .try_for_each(|path| file_storage.read(path).map(|_| ()))
            .context("Failed to load debug symbols")?;

        Ok(config)
    }
}
