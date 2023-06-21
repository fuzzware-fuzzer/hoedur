#[cfg(feature = "arm")]
pub(crate) mod arm;
#[cfg(feature = "arm")]
pub use arm::*;

impl Exception {
    pub(crate) fn pend(&self) {
        log::debug!("Exception::pend(self = {})", self);

        let cpu = crate::qcontrol::cpu_mut();

        // verify this is the only exception
        debug_assert_eq!(cpu.parent_obj.exception_index, -1);

        // set cpu exception
        cpu.parent_obj.exception_index = self.num();

        // exit TB execution at (before) next basic block
        if cpu.parent_obj.running {
            unsafe {
                qemu_sys::cpu_exit(&mut cpu.parent_obj);
            }
        }
    }
}
