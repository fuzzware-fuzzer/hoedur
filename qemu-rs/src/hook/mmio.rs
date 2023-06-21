use std::{convert::TryInto, os};

use crate::{
    lut::PcLookupTable, qcontrol_mut, qemu::handle_stop_request, Address, QemuCallbackGuard,
    QemuCallbackShared, Register,
};

pub struct MmioRegionCallbackHandler {
    cb: QemuCallbackShared,
    start: Address,
}

impl MmioRegionCallbackHandler {
    pub(crate) fn new(cb: QemuCallbackShared, start: Address) -> Self {
        Self { cb, start }
    }

    fn start(&self) -> Address {
        self.start
    }

    fn callback(&self) -> QemuCallbackGuard {
        self.cb.borrow_mut()
    }

    pub(crate) fn mmio_ops() -> qemu_sys::MemoryRegionOps {
        qemu_sys::MemoryRegionOps {
            read: Some(fuzzboard_mmio_read),
            write: Some(fuzzboard_mmio_write),
            endianness: qemu_sys::device_endian::DEVICE_NATIVE_ENDIAN,
            ..qemu_sys::MemoryRegionOps::default()
        }
    }

    pub(crate) fn dma_ops() -> qemu_sys::MemoryRegionOps {
        qemu_sys::MemoryRegionOps {
            read: Some(fuzzboard_dma_read),
            write: Some(fuzzboard_dma_write),
            ..Self::mmio_ops()
        }
    }
}

fn mmio_callback<'a>(
    opaque: *mut os::raw::c_void,
    offset: qemu_sys::hwaddr,
) -> (&'a mut MmioRegionCallbackHandler, Option<Address>, Address) {
    let cb_handler = unsafe { (opaque as *mut MmioRegionCallbackHandler).as_mut() }
        .expect("RegionCallbackHandler is null, this should never happen");
    let addr = (cb_handler.start() as u64 + offset)
        .try_into()
        .expect("addr overflow");

    let mem_io_pc = crate::qcontrol::cpu().parent_obj.mem_io_pc;
    let pc = (mem_io_pc != 0).then(|| {
        PcLookupTable::lock()
            .get_guest_pc(mem_io_pc)
            .expect("resolve PC from retaddr failed")
    });

    if let Some(pc) = pc {
        log::trace!("mmio_access(pc = {:#x?}, addr = {:#x?})", pc, addr);
        qcontrol_mut().set_register(Register::PC, pc);
    }

    (cb_handler, pc, addr)
}

extern "C" fn fuzzboard_mmio_read(
    opaque: *mut os::raw::c_void,
    addr: qemu_sys::hwaddr,
    size: os::raw::c_uint,
) -> u64 {
    let (cb_handler, pc, addr) = mmio_callback(opaque, addr);

    let value = if let Some(pc) = pc {
        cb_handler
            .callback()
            .on_read(pc, addr, size as u8)
            .expect("mmio read hook failed")
    } else {
        log::debug!(
            "mem_io_pc == 0, assuming MMIO fetch of instruction at {:#x?}, skip MMIO read handler",
            addr
        );
        undefined_instruction(size as u8)
    };

    log::trace!(
        "fuzzboard_mmio_read(pc = {:x?}, addr = {:#x?}, size = {:#x?}) -> value = {:#x?}",
        pc,
        addr,
        size,
        value
    );
    handle_stop_request();

    value
}

extern "C" fn fuzzboard_mmio_write(
    opaque: *mut os::raw::c_void,
    addr: qemu_sys::hwaddr,
    data: u64,
    size: os::raw::c_uint,
) {
    let (cb_handler, pc, addr) = mmio_callback(opaque, addr);

    if let Some(pc) = pc {
        cb_handler
            .callback()
            .on_write(pc, addr, data, size as u8)
            .expect("mmio write hook failed");
    } else {
        // NOTE: this is likely caused by a corrupted SP aiming at a MMIO region
        // NVIC will push registers to the stack on an exception which causes the `mem_io_pc` to be unset
        log::debug!(
            "mem_io_pc == 0, assuming MMIO write to {:#x?} by QEMU, skip MMIO write handler",
            addr
        );
    }

    log::trace!(
        "fuzzboard_mmio_write(pc = 0x{:x?}, addr = {:#x?}, data = {:#x?}, size = {:#x?})",
        pc,
        addr,
        data,
        size
    );
    handle_stop_request();
}

extern "C" fn fuzzboard_dma_read(
    opaque: *mut os::raw::c_void,
    addr: qemu_sys::hwaddr,
    size: os::raw::c_uint,
) -> u64 {
    log::trace!(
        "fuzzboard_dma_read(addr = {:#x?}, size = {:#x?})",
        addr,
        size
    );
    fuzzboard_mmio_read(opaque, 0, size)
}

extern "C" fn fuzzboard_dma_write(
    opaque: *mut os::raw::c_void,
    addr: qemu_sys::hwaddr,
    data: u64,
    size: os::raw::c_uint,
) {
    log::trace!(
        "fuzzboard_dma_write(addr = {:#x?}, data = {:#x?}, size = {:#x?})",
        addr,
        data,
        size
    );
    fuzzboard_mmio_write(opaque, 0, data, size)
}

#[cfg(feature = "arm")]
fn undefined_instruction(size: u8) -> u64 {
    match size {
        4 => 0xe7f000f0,
        2 => 0xde00,
        _ => {
            panic!("invalid MMIO fetch size {size:#x?}: should either be 2 byte (Thumb) or 4 (ARM)")
        }
    }
}

#[cfg(not(feature = "arm"))]
fn undefined_instruction(_: u8) -> u64 {
    0xdead_beef_dead_beef
}
