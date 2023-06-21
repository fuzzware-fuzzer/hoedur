use crate::{qemu_plugin_mem_rw, qemu_plugin_meminfo_t, MemOp, MemOpIdx};

fn get_oi(info: qemu_plugin_meminfo_t) -> MemOpIdx {
    info & 0xffff
}

fn get_memop(oi: MemOpIdx) -> MemOp {
    MemOp(oi >> 4)
}

pub fn size(info: qemu_plugin_meminfo_t) -> u8 {
    1 << (get_memop(get_oi(info)).0 & MemOp::MO_SIZE.0)
}

pub fn is_sign_extended(info: qemu_plugin_meminfo_t) -> bool {
    (get_memop(get_oi(info)).0 & MemOp::MO_SIGN.0) == MemOp::MO_SIGN.0
}

pub fn is_big_endian(info: qemu_plugin_meminfo_t) -> bool {
    (get_memop(get_oi(info)).0 & MemOp::MO_BSWAP.0) == MemOp::MO_BE.0
}

pub fn is_store(info: qemu_plugin_meminfo_t) -> bool {
    const MEM_STORE: u32 = qemu_plugin_mem_rw::QEMU_PLUGIN_MEM_W.0;

    ((info >> 16) & MEM_STORE) == MEM_STORE
}
