use std::fmt::Debug;

use anyhow::{Context, Result};
use common::{config::emulator::FIX_TASK_SWITCH_EDGE, FxHashMap};
use modeling::hardware::Input;
use qemu_rs::{
    board::Board, qcontrol, Address, CpuException, CpuModel, Event, Exception, NvicException,
    Register,
};

use crate::{debug, EmulatorData};

#[derive(Debug, Clone)]
pub enum ArmEmulator {
    Arm(ExceptionData),
    CortexM(NvicData),
}

pub type ArmEmulatorSnapshot = ArmEmulator;

#[derive(Debug, Default, Clone)]
pub struct ExceptionData {
    mode: Option<qemu_rs::register::Mode>,
    mode_stack: Vec<qemu_rs::register::Mode>,
}

#[derive(Debug, Default, Clone)]
pub struct NvicData {
    catch_exception: Option<CatchException>,
    exception_stack: Vec<qemu_rs::NvicException>,
    process_stack: FxHashMap<Address, u64>,
    catch_exit: Option<Address>,
    systick: bool,
}

#[derive(Debug, Clone)]
struct CatchException {
    pc: Address,
    lr: Address,
    cpu_exception: qemu_rs::CpuException,
}

struct EmulatorNvicException {
    pc: Address,
    lr: Address,
    exception: Option<(Exception, bool)>,
}

impl ExceptionData {
    fn on_exception(&mut self) {
        debug_assert_eq!(self.mode, None);

        self.mode = qemu_rs::register::Mode::from_cpsr(
            qemu_rs::qcontrol().register(qemu_rs::Register::CPSR),
        )
        .ok();
    }

    fn on_exception_level_change(&mut self) -> Option<usize> {
        if let Some(mode) = self.mode.take() {
            self.mode_stack.push(mode);
            None
        } else {
            // TODO: maybe multiple exception return, maybe mode switch without return
            self.mode_stack.pop().map(|_| 1)
        }
    }
}

impl NvicData {
    pub fn new(systick: bool) -> Self {
        Self {
            systick,
            ..Self::default()
        }
    }

    // TODO: refactor emulator/systick coupling
    fn update_systick(&mut self, ticks: usize) {
        if qemu_rs::systick().tick(ticks as u32) && self.systick {
            qemu_rs::request_interrupt_injection(Exception::from(qemu_rs::NvicException::from(
                qemu_rs::InternalException::SysTick,
            )));
        }
    }

    fn next_systick(&self) -> Option<usize> {
        qemu_rs::systick().ticks().map(|ticks| ticks as usize)
    }

    fn on_basic_block(&mut self) -> Result<Option<EmulatorNvicException>> {
        // catch nvic exception
        Ok(
            if let Some(CatchException {
                pc,
                lr,
                cpu_exception,
            }) = self.catch_exception.take()
            {
                // check if we got an exception (only after CPU-IRQ and exception chaining)
                let nvic_exception = qcontrol().nvic_exception();
                let mut exception = None;

                // new exception != previous exception (was not a return)
                log::trace!("exception_stack = {:?}", self.exception_stack);
                if self.exception_stack.last() != Some(&nvic_exception) {
                    // exception is valid (not zero after last exception return)
                    if nvic_exception.is_valid() {
                        // detect tail chaining (valid NVIC exception after exception exit)
                        let tail_chain = cpu_exception == qemu_rs::CpuException::ExceptionExit;

                        exception = Some((nvic_exception.into(), tail_chain));
                        log::trace!("found NVIC exception: {:?}", exception);

                        self.exception_stack.push(nvic_exception);
                    }
                }

                Some(EmulatorNvicException { pc, lr, exception })
            } else {
                None
            },
        )
    }

    fn on_exception(&mut self, pc: Address, cpu_exception: qemu_rs::CpuException) {
        // single step to catch NVIC exception
        // also single step on `ExceptionExit` to catch chained exceptions
        self.catch_exception = Some(CatchException {
            pc,
            lr: qcontrol().register(Register::LR),
            cpu_exception,
        });
    }

    fn on_exception_exit(&mut self) {
        let exception = self.exception_stack.pop();
        debug_assert!(exception.is_some());
    }
}

impl ArmEmulator {
    pub fn new(cpu: CpuModel, board: Board) -> Self {
        if cpu.has_nvic() {
            Self::CortexM(NvicData::new(board.systick()))
        } else {
            Self::Arm(ExceptionData::default())
        }
    }

    pub fn snapshot_create(&self) -> Result<ArmEmulatorSnapshot> {
        Ok(self.clone())
    }

    pub fn snapshot_restore(&mut self, snapshot: &ArmEmulatorSnapshot) -> Result<()> {
        *self = snapshot.clone();
        Ok(())
    }

    pub(crate) fn available_interrupts(&self, force_raise: bool) -> Vec<Exception> {
        match self {
            ArmEmulator::Arm(_) => CpuException::available_interrupts(force_raise).to_vec(),
            ArmEmulator::CortexM(_) => NvicException::available_interrupts(force_raise),
        }
    }

    pub(crate) fn update_basic_block_count<I: Input + Debug>(
        emulator: &mut EmulatorData<I>,
        ticks: usize,
    ) {
        if let ArmEmulator::CortexM(nvic) = &mut emulator.arch {
            nvic.update_systick(ticks)
        }
    }

    pub(crate) fn next_basic_block_hook<I: Input + Debug>(
        emulator: &mut EmulatorData<I>,
    ) -> Option<usize> {
        // SysTick
        if let ArmEmulator::CortexM(nvic) = &mut emulator.arch {
            nvic.next_systick()
        } else {
            None
        }
    }

    pub(crate) fn on_basic_block<I: Input + Debug>(
        emulator: &mut EmulatorData<I>,
        _pc: Address,
    ) -> Result<()> {
        if let ArmEmulator::CortexM(nvic) = &mut emulator.arch {
            // catch ARM NVIC exception
            if let Some(EmulatorNvicException {
                pc,
                lr,
                exception: Some((nvic_exception, tail_chain)),
            }) = nvic.on_basic_block()?
            {
                // save last_location for tail chained exceptions (on_exception handler is not called)
                if tail_chain {
                    emulator.fix_exception_edge();
                }

                emulator.handle_exception(pc, lr, nvic_exception)?;
            } else if FIX_TASK_SWITCH_EDGE && qcontrol().nvic_exception().is_none() {
                // TODO: handle secure / non-secure mode
                if let Some(old_sp) = nvic.catch_exit.take() {
                    let sp = qcontrol().register(Register::SP);

                    // catch process/task switch (SP change)
                    if sp != old_sp {
                        // save previous location
                        let previous_last_location = qemu_rs::coverage::get_last_location();
                        let old = nvic.process_stack.insert(old_sp, previous_last_location);
                        if let Some(old_last_location) = old {
                            log::warn!("context switch: last_location {:016x} overwritten for task {:08x} (SP)", old_last_location, old_sp);
                        }
                        log::debug!("context switch: task {:08x} -> {:08x} (SP)", old_sp, sp);

                        // set last_location
                        let next_last_location = nvic.process_stack.remove(&sp);
                        qemu_rs::coverage::set_last_location(next_last_location.unwrap_or(0));
                        log::trace!(
                            "context switch: last_location {:016x} -> {:016x?}",
                            previous_last_location,
                            next_last_location
                        );

                        // add task switch to trace
                        emulator.on_task_switch_debug(old_sp, sp)?;
                    }
                }
            }
        }

        Ok(())
    }

    pub(crate) fn on_update<I: Input + Debug>(
        emulator: &mut EmulatorData<I>,
        event: Event,
    ) -> Result<()> {
        match event {
            Event::ExceptionLevelChange => {
                if let ArmEmulator::Arm(data) = &mut emulator.arch {
                    if let Some(exit_count) = data.on_exception_level_change() {
                        for _ in 0..exit_count {
                            if let Err(err) = emulator.handle_exception_exit() {
                                log::error!("Failed to emit exception exit: {:#x?}", err);
                            }
                        }
                    }
                }
            }
            Event::SysTickGetTicks => emulator.update_basic_block_count()?,
            Event::SysTickChanged => emulator.set_next_basic_block_hook(false),
        }

        Ok(())
    }

    pub(crate) fn on_exception<I: Input + Debug>(
        emulator: &mut EmulatorData<I>,
        exception: Exception,
    ) -> Result<bool> {
        let pc = qcontrol().register(Register::PC);

        // don't filter any exception
        const FORWARD: bool = true;

        // single step and catch NVIC exception
        match &mut emulator.arch {
            ArmEmulator::Arm(data) => data.on_exception(),
            ArmEmulator::CortexM(nvic) => {
                // NVIC exception (e.g. from abort) => skip single step
                if exception.as_nvic().is_some() {
                    emulator.fix_exception_edge();
                    emulator.handle_exception(pc, debug::ra(), exception)?;
                    return Ok(FORWARD);
                }

                let cpu_exception = exception
                    .as_cpu()
                    .with_context(|| format!("Invalid CPU Exception: {exception:#x?}"))?;

                // save stack pointer on exception enter
                if FIX_TASK_SWITCH_EDGE && qcontrol().nvic_exception().is_none() {
                    if let Some(sp) = nvic.catch_exit {
                        log::error!(
                            "multiple exception enter before exception exit, previous SP = {:016x?}",
                            sp
                        );
                    }

                    // TODO: handle secure / non-secure mode
                    nvic.catch_exit = Some(qcontrol().register(Register::SP));
                }

                nvic.on_exception(pc, cpu_exception);
                emulator.update_basic_block_count()?;
                emulator.set_next_basic_block_hook(true);

                // catch exception exit
                if cpu_exception == qemu_rs::CpuException::ExceptionExit {
                    emulator.handle_exception_exit()?;
                    return Ok(FORWARD);
                }
            }
        }

        emulator.fix_exception_edge();

        // ignore CPU exceptions when NVIC is available
        if let ArmEmulator::CortexM(_) = &mut emulator.arch {
            return Ok(FORWARD);
        }

        emulator.handle_exception(pc, debug::ra(), exception)?;

        Ok(FORWARD)
    }

    pub(crate) fn on_exception_exit<I: Input + Debug>(
        emulator: &mut EmulatorData<I>,
    ) -> Result<()> {
        if let ArmEmulator::CortexM(nvic) = &mut emulator.arch {
            nvic.on_exception_exit();
            emulator.update_basic_block_count()?;
            emulator.set_next_basic_block_hook(true);
        }

        Ok(())
    }
}
