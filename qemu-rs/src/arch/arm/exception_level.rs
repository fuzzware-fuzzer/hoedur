use crate::{hook::hooks, Event};

extern "C" fn el_change_hook_rs(cpu: *mut qemu_sys::ARMCPU, opaque: *mut std::ffi::c_void) {
    log::trace!("el_change_hook(cpu = {:#x?}, opaque = {:#x?})", cpu, opaque);

    hooks()
        .on_update(Event::ExceptionLevelChange)
        .expect("update hook failed");
}

pub(crate) fn register_change_hook() {
    unsafe {
        qemu_sys::arm_register_el_change_hook(
            crate::qcontrol::cpu_mut(),
            Some(el_change_hook_rs),
            std::ptr::null_mut(),
        );
    }
}
