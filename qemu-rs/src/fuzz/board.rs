use std::{mem, os};

use anyhow::{bail, Result};

use qemu_sys::{cstr, memory_region_init_alias};

use crate::{
    board::Board, hook::mmio::MmioRegionCallbackHandler, memory, CpuModel, QemuCallbackShared,
    QemuStateControl,
};

pub const TYPE_FUZZ_BOARD: *const i8 = cstr!("fuzz-board");

// Global Qemu Initialization Struct
struct QemuInit {
    cpu: CpuModel,
    #[cfg_attr(not(feature = "arm"), allow(dead_code))]
    board: Board,
    memory_maps: Vec<memory::QemuMemoryMap>,
    callback: QemuCallbackShared,
}

static mut QEMU_INIT: Option<QemuInit> = None;
static mut QEMU_STATE: QemuStateControl = QemuStateControl::new();

pub(super) fn cpu_model() -> CpuModel {
    unsafe { QEMU_INIT.as_ref() }
        .expect("QemuInit is empty")
        .cpu
}

impl QemuStateControl {
    pub(crate) fn get_ref() -> &'static QemuStateControl {
        unsafe { &QEMU_STATE }
    }

    pub(crate) fn get_mut() -> &'static mut QemuStateControl {
        unsafe { &mut QEMU_STATE }
    }
}

#[cfg(feature = "arm")]
pub type CpuState = qemu_sys::CPUARMState;

#[derive(Debug)]
#[repr(C)]
pub(crate) struct FuzzBoardState {
    parent: qemu_sys::SysBusDevice,
    #[cfg(feature = "arm")]
    armv7m: qemu_sys::ARMv7MState,
}

#[cfg(feature = "arm")]
impl FuzzBoardState {
    pub(crate) fn has_nvic(&self) -> bool {
        !self.armv7m.nvic.cpu.is_null()
    }

    pub(crate) fn nvic(&self) -> Option<&qemu_sys::NVICState> {
        self.has_nvic().then_some(&self.armv7m.nvic)
    }

    pub(crate) fn nvic_mut(&mut self) -> Option<&mut qemu_sys::NVICState> {
        if self.has_nvic() {
            Some(&mut self.armv7m.nvic)
        } else {
            None
        }
    }
}

extern "C" fn fuzzboard_init(obj: *mut qemu_sys::Object) {
    log::trace!("fuzzboard_init");

    let state = unsafe { (obj as *mut FuzzBoardState).as_mut() }.unwrap();
    log::trace!("state = {:x?}", state);

    #[cfg(feature = "arm")]
    if cpu_model().has_nvic() {
        unsafe {
            qemu_sys::object_initialize_child_internal(
                obj as _,
                cstr!("armv7m"),
                (&mut state.armv7m) as *mut _ as _,
                mem::size_of::<qemu_sys::ARMv7MState>() as u64,
                cstr!("armv7m"),
            )
        }
    }
}

extern "C" fn fuzzboard_realize(dev: *mut qemu_sys::DeviceState, _errp: *mut *mut qemu_sys::Error) {
    log::trace!("fuzzboard_realize");
    use qemu_sys::{
        get_system_memory, memory_region_add_subregion, memory_region_init_io,
        memory_region_init_ram, memory_region_init_ram_ptr, memory_region_reset_dirty,
        memory_region_set_log, memory_region_set_readonly,
    };

    let fzboard_state = unsafe { (dev as *mut FuzzBoardState).as_mut() }.unwrap();
    log::trace!("state = {:x?}", fzboard_state);

    let system_memory = unsafe { get_system_memory() };

    let qinit = unsafe { QEMU_INIT.take() }.expect("QemuInit is empty");

    let mmio_ops = Box::into_raw(Box::new(MmioRegionCallbackHandler::mmio_ops()));
    let dma_ops = Box::into_raw(Box::new(MmioRegionCallbackHandler::dma_ops()));

    for memory_map in qinit.memory_maps.into_iter() {
        log::debug!("memory_map = {:x?}", memory_map);

        // create memory region
        let region = Box::into_raw(Box::default());

        // init memory region
        let name = memory_map.name().as_ptr();
        let size = memory_map.size() as u64;
        let mut callback_handler = None;
        match memory_map.data() {
            memory::QemuMemoryData::Zero { .. } => unsafe {
                memory_region_init_ram(region, dev as _, name, size, &mut qemu_sys::error_fatal)
            },
            memory::QemuMemoryData::File { ref data, .. } => unsafe {
                memory_region_init_ram_ptr(region, dev as _, name, size, data.as_ptr() as _)
            },
            memory::QemuMemoryData::Mmio { dma } => {
                let mut callback_handler_box = Box::new(MmioRegionCallbackHandler::new(
                    qinit.callback.clone(),
                    memory_map.start(),
                ));
                let opaque = callback_handler_box.as_mut() as *mut _;

                unsafe {
                    memory_region_init_io(
                        region,
                        dev as _,
                        if !dma { mmio_ops } else { dma_ops },
                        opaque as _,
                        name,
                        size,
                    )
                }

                callback_handler.replace(callback_handler_box);
            }
        };

        // set memory region readonly (ROM)
        unsafe { memory_region_set_readonly(region, memory_map.readonly()) }

        // enable dirty bitmap for R/W regions (RAM)
        if memory_map.dirty_map() {
            unsafe {
                memory_region_set_log(region, true, qemu_sys::DIRTY_MEMORY_VGA);
                memory_region_reset_dirty(region, 0, size, qemu_sys::DIRTY_MEMORY_VGA);
            }
        }

        // add region into system memory
        unsafe { memory_region_add_subregion(system_memory, memory_map.start() as u64, region) }

        // create alias memory regions
        for alias in memory_map.alias() {
            let alias_region = Box::into_raw(Box::default());

            unsafe {
                memory_region_init_alias(
                    alias_region,
                    dev as _,
                    alias.name().as_ptr(),
                    region,
                    alias.base_offset() as u64,
                    size,
                );
                memory_region_set_readonly(alias_region, memory_map.readonly());
                memory_region_add_subregion(system_memory, alias.start() as u64, alias_region);
            };
        }

        // keep a reference
        QemuStateControl::get_mut()
            .add_memory_map(memory_map, callback_handler, region)
            .expect("memory mapping is valid");
    }

    // init ARM CPU
    #[cfg(feature = "arm")]
    if qinit.cpu.has_nvic() {
        let armv7m = &mut fzboard_state.armv7m as *mut _;
        unsafe {
            qemu_sys::qdev_prop_set_string(armv7m as _, cstr!("cpu-type"), qinit.cpu.as_cstr());
            qemu_sys::qdev_prop_set_uint32(armv7m as _, cstr!("num-irq"), qinit.board.num_irq());
            if let Some(init_svtor) = qinit.board.init_svtor() {
                qemu_sys::qdev_prop_set_uint32(armv7m as _, cstr!("init-svtor"), init_svtor);
            }
            if let Some(init_nsvtor) = qinit.board.init_nsvtor() {
                qemu_sys::qdev_prop_set_uint32(armv7m as _, cstr!("init-nsvtor"), init_nsvtor);
            }
            qemu_sys::qdev_connect_clock_in(
                armv7m as _,
                cstr!("cpuclk"),
                qemu_sys::clock_new(armv7m as _, cstr!("CPUCLK")),
            );
        }

        // add memory to cpu
        unsafe {
            qemu_sys::object_property_set_link(
                armv7m as _,
                cstr!("memory"),
                get_system_memory() as _,
                &mut qemu_sys::error_abort,
            );
        }
        if !unsafe { qemu_sys::sysbus_realize(armv7m as _, _errp) } {
            return;
        }

        crate::arm::systick::init_systick(dev, &mut fzboard_state.armv7m, qinit.callback.clone());
    }

    // keep a reference
    QemuStateControl::get_mut().set_board_state(fzboard_state);
}

extern "C" fn fuzzboard_class_init(oc: *mut qemu_sys::ObjectClass, _data: *mut os::raw::c_void) {
    log::trace!("fuzzboard_class_init");

    let dc = unsafe { (oc as *mut qemu_sys::DeviceClass).as_mut() }.unwrap();
    log::trace!("dc = {:x?}", dc);

    dc.realize = Some(fuzzboard_realize);
}

extern "C" fn fuzzboard_register_types() {
    log::trace!("fuzzboard_register_types");
    use qemu_sys::type_register_static;

    let fuzzboard = Box::into_raw(Box::new(qemu_sys::TypeInfo {
        name: TYPE_FUZZ_BOARD,
        parent: cstr!(qemu_sys::TYPE_SYS_BUS_DEVICE),
        instance_size: mem::size_of::<FuzzBoardState>() as u64,
        instance_init: Some(fuzzboard_init),
        class_init: Some(fuzzboard_class_init),
        ..qemu_sys::TypeInfo::default()
    }));

    unsafe {
        type_register_static(fuzzboard);
    }
}

pub(crate) fn register(
    cpu: CpuModel,
    board: Board,
    memory: Vec<memory::QemuMemoryMap>,
    mmio_callback: QemuCallbackShared,
) -> Result<()> {
    log::trace!("register");
    use qemu_sys::register_module_init;

    let qinit = QemuInit {
        cpu,
        board,
        memory_maps: memory,
        callback: mmio_callback,
    };

    if unsafe { QEMU_INIT.replace(qinit) }.is_some() {
        bail!("Existing memory maps found, this should never happen!");
    }

    unsafe {
        register_module_init(
            Some(fuzzboard_register_types),
            qemu_sys::module_init_type::MODULE_INIT_QOM,
        );
    }

    Ok(())
}

pub(crate) fn drop_qemu_state_control() {
    unsafe {
        QEMU_STATE = QemuStateControl::new();
    }
}
