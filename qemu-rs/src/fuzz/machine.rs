use std::{ffi::c_void, mem};

use qemu_sys::cstr;

use crate::fuzz::board::{cpu_model, TYPE_FUZZ_BOARD};

pub const TYPE_FUZZ_MACHINE: *const i8 = cstr!("fuzz-machine");

#[cfg(feature = "arm")]
pub type Cpu = qemu_sys::ARMCPU;

extern "C" fn fuzzmachine_init(machine: *mut qemu_sys::MachineState) {
    log::trace!("fuzzmachine_init");

    let machine = unsafe { machine.as_mut() }.unwrap();
    log::trace!("machine = {:x?}", machine);
    use qemu_sys::{qdev_new, sysbus_realize_and_unref};

    #[cfg(feature = "arm")]
    let has_nvic = cpu_model().has_nvic();
    #[cfg(not(feature = "arm"))]
    let has_nvic = false;

    if !has_nvic {
        let cpu_ptr = unsafe { qemu_sys::cpu_create(machine.cpu_type) };
        let cpu = unsafe { (cpu_ptr as *mut Cpu).as_mut() }.unwrap();
        log::trace!("cpu = {:x?}", cpu);

        unsafe {
            qemu_sys::cpu_reset(cpu_ptr);
        };

        // TODO: add cpu feature support
        // cc->parse_features(cpu_type, model_pieces[1], &error_fatal);
    }

    let dev = unsafe { qdev_new(TYPE_FUZZ_BOARD) };
    unsafe { sysbus_realize_and_unref(dev as _, &mut qemu_sys::error_fatal) };
}

extern "C" fn fuzzmachine_class_init(oc: *mut qemu_sys::ObjectClass, _data: *mut c_void) {
    log::trace!("fuzzmachine_class_init");

    let mc = unsafe { (oc as *mut qemu_sys::MachineClass).as_mut() }.unwrap();
    log::trace!("mc = {:x?}", mc);

    mc.init = Some(fuzzmachine_init);
    mc.desc = cstr!("Hoedur Machine");
    mc.max_cpus = 1;
    mc.default_cpu_type = cpu_model().as_cstr();
    mc.default_ram_id = cstr!("ram");
    mc.default_ram_size = 0;
}

extern "C" fn fuzzmachine_register_types() {
    log::trace!("fuzzmachine_register_types");
    use qemu_sys::type_register_static;

    let fuzzmachine = Box::new(qemu_sys::TypeInfo {
        name: TYPE_FUZZ_MACHINE,
        parent: cstr!(qemu_sys::TYPE_MACHINE),
        class_init: Some(fuzzmachine_class_init),
        ..qemu_sys::TypeInfo::default()
    });
    unsafe { type_register_static(fuzzmachine.as_ref()) };
    mem::forget(fuzzmachine);
}

pub fn register() {
    log::trace!("register");
    use qemu_sys::register_module_init;

    unsafe {
        register_module_init(
            Some(fuzzmachine_register_types),
            qemu_sys::module_init_type::MODULE_INIT_QOM,
        );
    }
}
