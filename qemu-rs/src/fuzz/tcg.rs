use std::{
    ffi::c_void,
    mem::{self, MaybeUninit},
    sync::atomic,
};

use qemu_sys::cstr;

const TYPE_FUZZ_TCG_ACCEL: *const i8 = cstr!("fuzz-tcg-accel");
const TYPE_FUZZ_TCG_ACCEL_OPS: *const i8 = cstr!("fuzz-tcg-accel-ops");

static INIT_DONE: atomic::AtomicBool = atomic::AtomicBool::new(false);
static mut ALLOWED: bool = true;
static mut TCG_THREAD: qemu_sys::QemuThread = qemu_sys::QemuThread { thread: 0 };
static mut TCG_HALT_COND: MaybeUninit<qemu_sys::QemuCond> =
    MaybeUninit::<qemu_sys::QemuCond>::uninit();

extern "C" fn create_vcpu_thread(cpu: *mut qemu_sys::CPUState) {
    log::trace!("create_vcpu_thread");

    unsafe {
        qemu_sys::tcg_cpu_init_cflags(cpu, false);
    }

    // for now we don't support multiple CPU's, verify there are none.
    // our TCG wrapping also has no multi-threaded setting
    assert_eq!(
        unsafe { qemu_sys::current_machine.as_ref() }
            .unwrap()
            .smp
            .max_cpus,
        1
    );

    let cpu = unsafe { cpu.as_mut() }.unwrap();
    log::trace!("cpu = {:?}", cpu);

    unsafe {
        qemu_sys::qemu_thread_get_self(&mut TCG_THREAD);

        TCG_HALT_COND.write(qemu_sys::QemuCond::default());
        qemu_sys::qemu_cond_init(TCG_HALT_COND.assume_init_mut());
    };

    // set the cpu thread
    cpu.thread = unsafe { &mut TCG_THREAD };
    cpu.halt_cond = unsafe { TCG_HALT_COND.assume_init_mut() };
    // cpu.thread_id = first_cpu.thread_id;
    cpu.can_do_io = 1;
    cpu.created = true;
}

extern "C" fn kick_vcpu_thread(_cpu: *mut qemu_sys::CPUState) {
    log::trace!("kick_vcpu_thread");
}

extern "C" fn handle_interrupt(cpu: *mut qemu_sys::CPUState, mask: i32) {
    log::trace!("handle_interrupt");

    let cpu = unsafe { cpu.as_mut() }.unwrap();
    cpu.interrupt_request |= mask as u32;

    debug_assert!(unsafe { qemu_sys::qemu_cpu_is_self(cpu) });

    let icount_decr = unsafe { cpu.icount_decr_ptr.as_mut() }.unwrap();

    // NOTE: should use qatomic_set, but with the #define's in the qemu source that's pita
    // qatomic_set(&cpu_neg(cpu)->icount_decr.u16.high, -1);
    icount_decr.u16_.high = u16::MAX;
}

extern "C" fn get_virtual_clock() -> i64 {
    unimplemented!();
}

extern "C" fn get_elapsed_ticks() -> i64 {
    unimplemented!();
}

fn tcg_cpu_init() {
    log::trace!("tcg_cpu_init");
    unsafe {
        // qemu_sys::rcu_register_thread();
        qemu_sys::tcg_register_thread();
    }

    let cpu = crate::qcontrol::cpu_mut();

    cpu.parent_obj.thread_id = unsafe { qemu_sys::qemu_get_thread_id() };
    cpu.parent_obj.can_do_io = 1;
    cpu.parent_obj.created = true;
    cpu.parent_obj.exit_request = false;

    unsafe {
        qemu_sys::qemu_guest_random_seed_thread_part2(0);
    }

    crate::hook::interrupt::set_do_interrupt_hook(cpu);
}

pub fn tcg_cpu_loop(debug: bool) {
    log::trace!("tcg_cpu_loop");

    if !INIT_DONE.swap(true, atomic::Ordering::SeqCst) {
        tcg_cpu_init()
    }

    let cpu_ref = crate::qcontrol::cpu_mut();

    unsafe {
        let cpu = cpu_ref as *mut _ as _;

        // NOTE: CPU state is mutated by QEMU
        #[allow(clippy::while_immutable_condition)]
        while !cpu_ref.parent_obj.stop && !cpu_ref.parent_obj.exit_request {
            // process async work QEMU queued
            if !qemu_sys::cpu_work_list_empty(cpu) {
                log::trace!("!cpu_work_list_empty: process_queued_cpu_work()");
                qemu_sys::process_queued_cpu_work(cpu);
            }

            // handle GDB events
            if debug {
                handle_io_events(true);
            }

            if qemu_sys::cpu_can_run(cpu) {
                // run TCG
                qemu_sys::cpu_exec_start(cpu);
                let ret = qemu_sys::cpu_exec(cpu);
                log::trace!("cpu_exec() = {:#x?}", ret);
                qemu_sys::cpu_exec_end(cpu);

                match ret as u32 {
                    qemu_sys::EXCP_INTERRUPT => {
                        log::trace!("EXCP_INTERRUPT");
                    }
                    qemu_sys::EXCP_HLT => {
                        log::trace!("EXCP_HLT");
                    }
                    qemu_sys::EXCP_HALTED => {
                        log::trace!("EXCP_HALTED");
                        crate::hook::wait_for_interrupt(true);
                    }
                    qemu_sys::EXCP_YIELD => {
                        // TODO: yield CPU timeslice to antoher vCPU
                        log::debug!("EXCP_YIELD");
                        crate::hook::wait_for_interrupt(false);
                    }
                    qemu_sys::EXCP_DEBUG => {
                        log::debug!("EXCP_DEBUG");
                        gdb_breakpoint(cpu);
                        break;
                    }
                    qemu_sys::EXCP_ATOMIC => {
                        log::debug!("EXCP_ATOMIC");
                        qemu_sys::cpu_exec_step_atomic(cpu);
                        break;
                    }
                    excp => log::warn!("unexpected CPU exception: {:#x?}", excp),
                }
            } else if debug {
                // wait for GDB event (avoid busy-loop)
                handle_io_events(false);
            } else {
                log::warn!("!cpu_can_run");
            }
        }

        cpu_ref.parent_obj.exit_request = false;
    }
}

pub fn gdb_breakpoint(cpu: *mut qemu_sys::CPUState) {
    unsafe {
        qemu_sys::cpu_handle_guest_debug(cpu);
        qemu_sys::runstate_set(qemu_sys::RunState::RUN_STATE_DEBUG);
        qemu_sys::vm_state_notify(false, qemu_sys::RunState::RUN_STATE_DEBUG);
    }
}

fn handle_io_events(nonblocking: bool) {
    unsafe {
        qemu_sys::main_loop_wait(i32::from(nonblocking));
    }
}

extern "C" fn tcg_init_machine(_ms: *mut qemu_sys::MachineState) -> i32 {
    log::trace!("tcg_init_machine");

    // 0 = default (1 GiB), min = 1 MiB
    let tb_size = 0;

    #[cfg(debug_assertions)]
    let splitwx = -1;
    #[cfg(not(debug_assertions))]
    let splitwx = 0;

    unsafe {
        qemu_sys::tcg_allowed = true;
        qemu_sys::page_init();
        qemu_sys::tb_htable_init();
        qemu_sys::tcg_init(tb_size, splitwx, 1);
        qemu_sys::hoedur_tcg_prologue_init();
    }

    0
}

extern "C" fn tcg_accel_ops_init(ops: *mut qemu_sys::AccelOpsClass) {
    let ops = unsafe { ops.as_mut().expect("ops is not null") };
    ops.create_vcpu_thread = Some(create_vcpu_thread);
    ops.kick_vcpu_thread = Some(kick_vcpu_thread);
    ops.handle_interrupt = Some(handle_interrupt);
    ops.get_virtual_clock = Some(get_virtual_clock);
    ops.get_elapsed_ticks = Some(get_elapsed_ticks);
}

extern "C" fn tcg_accel_ops_class_init(oc: *mut qemu_sys::ObjectClass, _data: *mut c_void) {
    log::trace!("tcg_accel_ops_class_init");

    let ops = unsafe { (oc as *mut qemu_sys::AccelOpsClass).as_mut() }.unwrap();
    log::trace!("ops = {:x?}", ops);

    ops.ops_init = Some(tcg_accel_ops_init);
}

extern "C" fn tcg_accel_class_init(oc: *mut qemu_sys::ObjectClass, _data: *mut c_void) {
    log::trace!("tcg_accel_class_init");

    let ac = unsafe { (oc as *mut qemu_sys::AccelClass).as_mut() }.unwrap();
    log::trace!("ac = {:x?}", ac);

    ac.name = cstr!("fuzz-tcg");
    ac.init_machine = Some(tcg_init_machine);
    ac.allowed = unsafe { &mut ALLOWED };
}

extern "C" fn tcg_register_types() {
    log::trace!("tcg_register_types");

    // fuzz-accel
    let fuzz_accel = Box::new(qemu_sys::TypeInfo {
        name: TYPE_FUZZ_TCG_ACCEL,
        parent: cstr!(qemu_sys::TYPE_ACCEL),
        class_init: Some(tcg_accel_class_init),
        ..qemu_sys::TypeInfo::default()
    });
    unsafe { qemu_sys::type_register_static(fuzz_accel.as_ref()) };
    mem::forget(fuzz_accel);

    // fuzz-accel-ops
    let fuzz_accel = Box::new(qemu_sys::TypeInfo {
        name: TYPE_FUZZ_TCG_ACCEL_OPS,
        parent: cstr!(qemu_sys::TYPE_ACCEL_OPS),
        class_init: Some(tcg_accel_ops_class_init),
        abstract_: true,
        ..qemu_sys::TypeInfo::default()
    });
    unsafe { qemu_sys::type_register_static(fuzz_accel.as_ref()) };
    mem::forget(fuzz_accel);
}

pub fn register() {
    log::trace!("register");

    unsafe {
        qemu_sys::register_module_init(
            Some(tcg_register_types),
            qemu_sys::module_init_type::MODULE_INIT_QOM,
        );
    }
}
