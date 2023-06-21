use std::{
    env,
    ffi::CString,
    sync::atomic::{AtomicBool, Ordering},
};

use anyhow::{bail, Context, Result};
use common::{
    exit::{signal_term_point, EXIT, TERM},
    file_storage::FileStorage,
};
use signal_hook::consts::TERM_SIGNALS;

use crate::{
    board::Board,
    coverage,
    fuzz::{self, board::drop_qemu_state_control, tcg::tcg_cpu_loop},
    hook::{self, drop_qemu_hook},
    memory, Address, CpuModel, MemorySnapshot, QemuCallbackShared,
};

static QEMU_CREATED: AtomicBool = AtomicBool::new(false);
pub(crate) static QEMU_RUNNING: AtomicBool = AtomicBool::new(false);

pub fn init_qemu(
    cpu: CpuModel,
    board: Board,
    file_storage: &FileStorage,
    callback: QemuCallbackShared,
    memory_maps: Vec<memory::MemoryMap>,
    interrupt_trigger: Vec<Address>,
    exit_hooks: Vec<Address>,
    debug_hooks: Option<Vec<Address>>,
    trace_mode: bool,
) -> Result<()> {
    if QEMU_CREATED.swap(true, Ordering::Relaxed) {
        bail!("QEMU can only be instanced once per process.");
    }

    // qemu commandline args
    let args = qemu_args().context("Failed to collect qemu args")?;
    let mut args_ffi: Vec<_> = args
        .iter()
        .map(|arg| arg.as_ptr())
        .chain(vec![core::ptr::null()])
        .collect();

    // empty env for qemu
    let envs: Vec<std::ffi::CString> = vec![];
    let mut envs_ffi: Vec<_> = envs
        .iter()
        .map(|env| env.as_ptr())
        .chain(vec![core::ptr::null()])
        .collect();

    // pre process memory maps for qemu
    let mut qemu_memory = Vec::with_capacity(memory_maps.len());
    for map in memory_maps {
        let qemu_map = map
            .as_qemu_memory_map(file_storage)
            .with_context(|| format!("Failed to preprocess memory map {map:x?}"))?;
        qemu_memory.push(qemu_map);
    }

    // create initial memory snapshot
    MemorySnapshot::init(&mut qemu_memory);

    // init our dynamic qemu types
    fuzz::tcg::register();
    fuzz::machine::register();
    fuzz::board::register(cpu, board, qemu_memory, callback.clone())
        .context("Failed to register fuzz-board type")?;

    // call qemu init
    unsafe {
        qemu_sys::qemu_init(
            args.len() as i32,
            args_ffi.as_mut_ptr() as _,
            envs_ffi.as_mut_ptr() as _,
        );
    }

    // set QEMU hooks
    hook::register_hooks(
        callback.clone(),
        interrupt_trigger,
        exit_hooks,
        debug_hooks,
        trace_mode,
    )?;

    // create coverage bitmap
    if !coverage::init_done() {
        coverage::init_coverage_bitmap();
    }

    Ok(())
}

fn qemu_args() -> Result<Vec<CString>> {
    // default qemu args
    let exe = env::current_exe()
        .context("Failed to get own executable path")?
        .display()
        .to_string();
    let args = vec![
        exe.as_str(),
        // fuzz machine
        "-machine",
        "fuzz",
        // use TCG
        "-accel",
        "fuzz-tcg",
        // use guest clock
        "-rtc",
        "clock=vm",
        // disable graphics
        "-nographic",
        // disable monitor
        "-monitor",
        "/dev/null",
    ];

    // convert args to CStrings for FFI
    args.into_iter()
        .map(|arg| {
            CString::new(arg).with_context(|| format!("Failed to create CString for arg {arg:?}"))
        })
        .collect()
}

pub fn set_signal_handler() -> Result<()> {
    // NOTE: DO NOT USE `log`! this may deadlock
    // NOTE: QEMU overwrites signal handlers, only set them up after QEMU init
    let set_exit = || {
        if !EXIT.swap(true, Ordering::SeqCst) {
            eprintln!("Received first term signal: clean exit at next opportunity");
        } else if !TERM.swap(true, Ordering::SeqCst) {
            eprintln!("Received second term signal: request QEMU stop");
            request_stop();
        } else {
            eprintln!("Received third term signal: force exit");
            signal_hook::low_level::exit(1);
        }
    };
    for signal in TERM_SIGNALS {
        unsafe {
            signal_hook::low_level::register(*signal, set_exit)
                .context("register signal handler")?;
        }
    }

    Ok(())
}

pub fn run() -> Result<Option<QemuStopReason>> {
    log::trace!("qemu::run");
    assert!(crate::get_next_basic_block_hook() < i64::MAX as u64);
    assert!(!QEMU_RUNNING.swap(true, Ordering::SeqCst));

    // resume_cpu() without qemu_cpu_kick(cpu)
    // undo halt in case we hit an infinite sleep
    {
        let cpu = crate::qcontrol::cpu_mut();
        cpu.parent_obj.stop = false;
        cpu.parent_obj.stopped = false;
        cpu.parent_obj.halted = 0;

        #[cfg(feature = "arm")]
        {
            cpu.parent_obj.crash_occurred = false;
        }
    }

    tcg_cpu_loop(false);

    assert!(QEMU_RUNNING.swap(false, Ordering::SeqCst));

    qemu_stop_reason()
}

pub fn request_stop() {
    log::trace!("qemu::request_stop");
    assert!(QEMU_RUNNING.load(Ordering::SeqCst));

    unsafe {
        qemu_sys::cpu_stop_current();
    }
}

pub(crate) fn handle_stop_request() {
    log::trace!("qemu::handle_stop_request");
    assert!(QEMU_RUNNING.load(Ordering::SeqCst));

    let cpu = crate::qcontrol::cpu_mut();

    // stop requested
    if cpu.parent_obj.stop {
        log::trace!("do requested QEMU stop");
        let cpu_ptr = cpu as *mut _ as *mut _;
        let cflags = cpu.parent_obj.tcg_cflags;

        if (cflags & qemu_sys::CF_LAST_IO) != 0 {
            log::trace!(
                "QEMU bail-out stop: cflags = {:#x?}, calling cpu_io_recompile",
                cflags
            );
            unsafe {
                qemu_sys::cpu_io_recompile(cpu_ptr, cpu.parent_obj.mem_io_pc);
            }
        } else {
            log::trace!(
                "QEMU bail-out stop: cflags = {:#x?}, calling cpu_loop_exit_noexc",
                cflags
            );
            unsafe {
                qemu_sys::cpu_loop_exit_noexc(cpu_ptr);
            }
        }

        unreachable!("QEMU longjmp should take control");
    }
}

pub fn drop() -> Result<()> {
    #[cfg(feature = "arm")]
    crate::systick::drop_systick();
    drop_qemu_state_control();
    drop_qemu_hook().context("Failed to drop qemu callback hooks")
}

#[derive(Debug)]
pub enum QemuStopReason {
    Panic,
    Reset,
    Shutdown,
    Unexpected(qemu_sys::ShutdownCause),
}

impl QemuStopReason {
    fn from_qemu(cause: qemu_sys::ShutdownCause) -> Option<Self> {
        Some(match cause {
            qemu_sys::ShutdownCause::SHUTDOWN_CAUSE_NONE => return None,
            qemu_sys::ShutdownCause::SHUTDOWN_CAUSE_GUEST_PANIC => Self::Panic,
            qemu_sys::ShutdownCause::SHUTDOWN_CAUSE_GUEST_RESET => Self::Reset,
            qemu_sys::ShutdownCause::SHUTDOWN_CAUSE_GUEST_SHUTDOWN => Self::Shutdown,
            _ => Self::Unexpected(cause),
        })
    }
}

fn qemu_stop_reason() -> Result<Option<QemuStopReason>> {
    let reset = QemuStopReason::from_qemu(unsafe { qemu_sys::qemu_reset_requested_get() });
    let shutdown = QemuStopReason::from_qemu(unsafe { qemu_sys::qemu_shutdown_requested_get() });
    log::debug!(
        "reset_request = {:x?}, shutdown_request = {:x?}",
        reset,
        shutdown
    );

    signal_term_point()?;

    // remove reset / shutdown request
    // NOTE: this is a bit wonky but saves us modifying the qemu source
    // `reset_requested` and `shutdown_requested` are both private
    if reset.is_some() {
        // save cpu state
        let cpu = crate::qcontrol::cpu_mut();
        let stop = cpu.parent_obj.stop;
        let exit_request = cpu.parent_obj.exit_request;

        unsafe {
            qemu_sys::qemu_system_reset_request(qemu_sys::ShutdownCause::SHUTDOWN_CAUSE_NONE);
        }

        // undo side effects of `qemu_system_reset_request`
        cpu.parent_obj.stop = stop;
        cpu.parent_obj.exit_request = exit_request;
        // cpu->icount_decr_ptr->u16.high
    }
    if shutdown.is_some() {
        unsafe {
            qemu_sys::qemu_system_shutdown_request(qemu_sys::ShutdownCause::SHUTDOWN_CAUSE_NONE);
        }
    }

    Ok(reset.or(shutdown))
}
