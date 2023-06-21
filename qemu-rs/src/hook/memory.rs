use std::sync::atomic::Ordering;

use anyhow::Context;
use qemu_sys::{tcg::TcgCallback, tcg_function};

use crate::{
    hook::{hooks, set_pc},
    lut::PcLookupTable,
    qcontrol,
    qemu::{handle_stop_request, QEMU_RUNNING},
    Register, USize,
};

tcg_function! {
    qemu_sys::TCG_CALL_NO_WRITE_GLOBALS;

    fn mem_access_hook(vaddr: u32, info: u32) {
        log::trace!("mem_access_hook(vaddr = {:#x?}, info = {:#x?})", vaddr, info);
        assert!(QEMU_RUNNING.load(Ordering::SeqCst));

        if let Some(memory) = qcontrol().memory_blocks().find(|mem| mem.contains(vaddr)) {
            let pc = qcontrol().register(Register::PC);

            // unpack meminfo, load value
            let info = info as qemu_sys::qemu_plugin_meminfo_t;
            let size = qemu_sys::mem::size(info);
            let store = qemu_sys::mem::is_store(info);
            let value = match size {
                1 => qcontrol().read::<u8, 1>(vaddr).map(|value| value as u64),
                2 => qcontrol().read::<u16, 2>(vaddr).map(|value| value as u64),
                4 => qcontrol().read::<u32, 4>(vaddr).map(|value| value as u64),
                8 => qcontrol().read::<u64, 8>(vaddr),
                _ => {
                    unreachable!("memory access at pc {:#x?}, addr {:#x?} with unexpected access size {:?}", pc, vaddr, size);
                }
            }.with_context(|| format!("memory access at pc {pc:#x?}, addr {vaddr:#x?} with size {size:?}")).expect("memory can be read");

            // log trace info
            let signed = qemu_sys::mem::is_sign_extended(info);
            let big_endian = qemu_sys::mem::is_big_endian(info);
            log::trace!(
                "mem_access_hook: pc = {:#x?}, addr = {:#x?}, value = {:#x?}, size = {:?}, signed = {:?}, big_endian = {:?}, store = {:?}",
                pc,
                vaddr,
                value,
                size,
                signed,
                big_endian,
                store
            );

            // call mem access hook
            match (memory.readonly, !store) {
                (true, true) => hooks().on_rom_read(pc, vaddr, value, size),
                (true, false) => hooks().on_rom_write(pc, vaddr, value, size),
                (false, true) => hooks().on_ram_read(pc, vaddr, value, size),
                (false, false) => hooks().on_ram_write(pc, vaddr, value, size),
            }
            .expect("memory access hook failed");
            handle_stop_request();
        } else {
            log::trace!("mem_access_hook: addr = {:#x?}, no backing memory", vaddr);
        }
    }
}

extern "C" fn rom_write_hook_rs(retaddr: usize, addr: USize, val: u64, size: u64) {
    log::trace!(
        "rom_write_hook_rs(retaddr = {:#x?}, addr = {:#08x?}, val = {:#x?}, size = {})",
        retaddr,
        addr,
        val,
        size
    );

    let pc = PcLookupTable::lock()
        .get_guest_pc(retaddr)
        .expect("resolve PC from retaddr failed");
    set_pc(pc);

    hooks()
        .on_rom_write(pc, addr, val, size as u8)
        .expect("rom write hook failed");
    handle_stop_request();
    assert!(!QEMU_RUNNING.load(Ordering::SeqCst));
}

extern "C" fn mem_access_hook_rs(
    oi: qemu_sys::MemOpIdx,
    rw: qemu_sys::qemu_plugin_mem_rw,
) -> *mut qemu_sys::TCGHelperInfo {
    log::trace!("mem_access_hook_rs(oi = {:#x?}, rw = {:x?})", oi, rw);

    MEM_ACCESS_HOOK_INFO.as_callback()
}

pub(super) fn register_hooks(trace: bool) {
    MEM_ACCESS_HOOK_INFO.register();

    unsafe {
        if trace {
            qemu_sys::mem_access_hook = Some(mem_access_hook_rs);
        }
        qemu_sys::rom_write_hook = Some(rom_write_hook_rs);
    }
}
