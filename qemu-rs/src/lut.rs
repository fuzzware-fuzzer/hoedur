use std::{io::Cursor, slice};

use anyhow::{bail, Context, Result};
use common::{hashbrown::hash_map::Entry, FxHashMap, FxHashSet};
use once_cell::sync::Lazy;
use parking_lot::{Mutex, MutexGuard};

use crate::Address;

type TbPtr = usize;

static PC_LUT: Lazy<Mutex<PcLookupTable>> = Lazy::new(|| Mutex::new(PcLookupTable::default()));
static LAST_IO_TB_PTR: Lazy<Mutex<FxHashSet<TbPtr>>> =
    Lazy::new(|| Mutex::new(FxHashSet::default()));

#[derive(Debug, Default)]
pub struct PcLookupTable {
    ret_pc: FxHashMap<usize, Address>,
}

impl PcLookupTable {
    pub fn lock<'a>() -> MutexGuard<'a, Self> {
        PC_LUT.lock()
    }

    pub fn get_guest_pc(&mut self, retaddr: usize) -> Result<Address> {
        Ok(match self.ret_pc.entry(retaddr) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => {
                let guest_pc =
                    search_guest_pc(retaddr).context("could not find pc of MMIO instruction")?;

                // don't cache LAST_IO instruction lookups
                if !is_last_io(retaddr)? {
                    *entry.insert(guest_pc)
                } else {
                    guest_pc
                }
            }
        })
    }

    pub fn clear(&mut self) {
        self.ret_pc.clear();
    }
}

unsafe fn tb(retaddr: usize) -> Result<&'static qemu_sys::TranslationBlock> {
    unsafe { qemu_sys::tcg_tb_lookup(retaddr).as_ref() }
        .with_context(|| format!("Could not find TranslationBlock for {retaddr:#x?}"))
}

fn tb_ptr(tb: &qemu_sys::TranslationBlock) -> TbPtr {
    tb.tc.ptr as TbPtr
}

pub(crate) fn set_last_io(tb: &qemu_sys::TranslationBlock) {
    LAST_IO_TB_PTR.lock().insert(tb_ptr(tb));
}

pub(crate) fn clear_last_io(tb: &qemu_sys::TranslationBlock) {
    LAST_IO_TB_PTR.lock().remove(&tb_ptr(tb));
}

fn is_last_io(retaddr: usize) -> Result<bool> {
    Ok(LAST_IO_TB_PTR
        .lock()
        .contains(&tb_ptr(unsafe { tb(retaddr).context("is LAST_IO check")? })))
}

fn search_guest_pc(retaddr: usize) -> Result<Address> {
    let tb = unsafe { tb(retaddr) }?;
    let mut pc = tb.pc;
    let mut host_pc = tb_ptr(tb);
    let search_data_ptr = unsafe { (tb.tc.ptr as *const u8).offset(tb.tc.size as isize) };
    let search_data = unsafe { slice::from_raw_parts(search_data_ptr, isize::MAX as usize) };
    let mut search_data = Cursor::new(search_data);

    let searched_pc = retaddr - qemu_sys::GETPC_ADJ as usize;
    if searched_pc < host_pc {
        bail!("searched pc not in TranslationBlock");
    }

    log::trace!("pc = {:#x?}, host_pc = {:#x?}, searched_pc = {:#x?}, search_data_ptr = {:#x?}, icount = {}", pc, host_pc, searched_pc, search_data_ptr, tb.icount);

    for _ in 0..tb.icount {
        // guest pc
        pc += leb128::read::signed(&mut search_data)
            .context("Failed to read guest pc offset from search_data")? as Address;

        // ignore other data fields
        for _ in 0..(qemu_sys::TARGET_INSN_START_WORDS - 1) {
            let _ = leb128::read::signed(&mut search_data)
                .context("Failed to read search_data value")?;
        }

        // host pc
        host_pc += leb128::read::signed(&mut search_data)
            .context("Failed to read host pc offset from search_data")? as usize;

        log::trace!("pc = {:#x?}, host_pc = {:#x?}", pc, host_pc);

        if host_pc > searched_pc {
            return Ok(pc);
        }
    }

    bail!("searched instruction not in TranslationBlock");
}
