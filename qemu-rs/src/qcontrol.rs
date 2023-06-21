use std::{ffi::CStr, fmt, slice};

use anyhow::{bail, Result};
use either::Either::{Left, Right};
use endiannezz::Primitive;

#[cfg(feature = "arm")]
use anyhow::Context;

use crate::{
    fuzz::{
        board::{CpuState, FuzzBoardState},
        machine,
    },
    hook::mmio::MmioRegionCallbackHandler,
    memory::{QemuMemoryData, QemuMemoryMap},
    snapshot::PageAddress,
    Address, Exception, Register, RegisterAccess, USize,
};

#[derive(Debug)]
pub struct QemuStateControl {
    board_state: Option<*mut FuzzBoardState>,
    memory: Vec<Memory>,
}

// we are dealing with pointers from QEMU, adding Send+Sync isn't going
// to cause more chaos then we already got in the first place
unsafe impl Send for QemuStateControl {}
unsafe impl Sync for QemuStateControl {}

pub(crate) struct Memory {
    qemu_memory_map: QemuMemoryMap,
    _callback_handler: Option<Box<MmioRegionCallbackHandler>>,
    region: *mut qemu_sys::MemoryRegion,
    raw_pointer: Option<(*mut ::std::os::raw::c_void, USize)>,
}

pub struct MemoryBlock<'a> {
    pub readonly: bool,
    pub start: Address,
    pub data: &'a [u8],
}

impl QemuStateControl {
    pub(crate) const fn new() -> Self {
        Self {
            board_state: None,
            memory: Vec::new(),
        }
    }

    pub(crate) fn set_board_state(&mut self, board_state: *mut FuzzBoardState) {
        if let Some(old_state) = self.board_state.replace(board_state) {
            log::debug!("old_state = {:#?}", old_state);
            panic!("Existing board_state found, this should never happen!");
        }
    }

    pub(crate) fn add_memory_map(
        &mut self,
        qemu_memory_map: QemuMemoryMap,
        callback_handler: Option<Box<MmioRegionCallbackHandler>>,
        region: *mut qemu_sys::MemoryRegion,
    ) -> Result<()> {
        let memory = Memory::new(qemu_memory_map, callback_handler, region);

        if !memory.qemu_memory_map.allow_overlap() {
            for other in &self.memory {
                if memory.overlaps_with(other) {
                    bail!(
                        "Memory region overlap:\n{:#x?}\n\noverlaps with\n\n{:#x?}.",
                        memory,
                        other
                    );
                }
            }
        }

        self.memory.push(memory);

        Ok(())
    }

    pub(crate) fn memory(&self) -> &[Memory] {
        &self.memory
    }

    pub(crate) fn memory_mut(&mut self) -> &mut [Memory] {
        &mut self.memory
    }

    pub fn memory_blocks(&self) -> impl Iterator<Item = MemoryBlock> {
        self.memory.iter().flat_map(|memory| memory.memory_blocks())
    }

    unsafe fn memory_pointer(
        &self,
        address: Address,
        len: Option<Address>,
        write: bool,
    ) -> Result<&mut [u8]> {
        // memory containing address exists
        if let Some(wrapper) = self
            .memory
            .iter()
            .find(|memory| memory.inner().contains(address))
        {
            let memory = wrapper.inner();

            if write && memory.readonly() {
                log::warn!("Write to ROM region at {:#x?}, use with caution", address);
            }

            let offset = memory
                .offset(address)
                .expect("Address within memory region has a valid offset");
            let start = offset as usize;

            let range = if let Some(len) = len {
                // verify end is within region
                if memory.contains(address + len - 1 as USize) {
                    let end = (offset + len) as usize;
                    Left(start..end)
                } else {
                    bail!("Memory region too short for access.")
                }
            } else {
                Right(start..)
            };

            // verify region has backing memory (RAM/ROM)
            if let Some(pointer) = unsafe { wrapper.pointer() } {
                match range {
                    Left(range) => Ok(&mut pointer[range]),
                    Right(range) => Ok(&mut pointer[range]),
                }
            } else {
                bail!("Memory region doesn't have backing memory.")
            }
        } else {
            bail!("Memory region not found.")
        }
    }

    pub fn read_into(&self, address: Address, data: &mut [u8]) -> Result<()> {
        let pointer = unsafe { self.memory_pointer(address, Some(data.len() as USize), false)? };
        data.copy_from_slice(pointer);
        Ok(())
    }

    pub fn write_from(&mut self, address: Address, data: &[u8]) -> Result<()> {
        let pointer = unsafe { self.memory_pointer(address, Some(data.len() as USize), true)? };
        pointer.copy_from_slice(data);
        Ok(())
    }

    pub fn read_cstr(&self, address: Address) -> Result<&'static CStr> {
        let pointer = unsafe { self.memory_pointer(address, None, false)? };
        Ok(unsafe { CStr::from_ptr(pointer.as_ptr() as _) })
    }

    pub fn read<T: Primitive<Buf = [u8; N]>, const N: usize>(&self, address: Address) -> Result<T> {
        let mut data = [0u8; N];
        self.read_into(address, &mut data)?;

        Ok(T::from_ne_bytes(data))
    }

    pub fn write<T: Primitive<Buf = [u8; N]>, const N: usize>(
        &mut self,
        address: Address,
        value: T,
    ) -> Result<()> {
        let data = value.to_ne_bytes();
        self.write_from(address, &data)
    }

    pub fn set_register(&mut self, register: Register, value: u32) {
        log::trace!("set_register {:?} = {:#x?}", register, value);
        cpu_state_mut().write(register, value);
    }

    pub fn register(&self, register: Register) -> u32 {
        cpu_state().read(register)
    }

    pub fn exception(&self) -> Exception {
        Exception::from(cpu().parent_obj.exception_index)
    }
}

#[cfg(feature = "arm")]
impl QemuStateControl {
    pub(crate) fn board(&self) -> Result<&FuzzBoardState> {
        unsafe { self.board_state.context("board state missing")?.as_ref() }
            .context("board state is nullptr")
    }

    pub(crate) fn board_mut(&mut self) -> Result<&mut FuzzBoardState> {
        unsafe { self.board_state.context("board state missing")?.as_mut() }
            .context("board state is nullptr")
    }

    pub fn nvic_exception(&self) -> crate::NvicException {
        crate::NvicException::from(cpu_state().v7m.exception)
    }
}

pub(crate) fn cpu() -> &'static machine::Cpu {
    unsafe { &*(qemu_sys::qemu_get_cpu(0) as *const machine::Cpu) }
}

pub(crate) fn cpu_mut() -> &'static mut machine::Cpu {
    unsafe { &mut *(qemu_sys::qemu_get_cpu(0) as *mut machine::Cpu) }
}

pub(crate) fn cpu_state() -> &'static CpuState {
    &cpu().env
}

pub(crate) fn cpu_state_mut() -> &'static mut CpuState {
    &mut cpu_mut().env
}

impl Memory {
    fn new(
        qemu_memory_map: QemuMemoryMap,
        callback_handler: Option<Box<MmioRegionCallbackHandler>>,
        region: *mut qemu_sys::MemoryRegion,
    ) -> Self {
        // keep a raw pointer into the memory region
        let raw_pointer = match qemu_memory_map.data() {
            QemuMemoryData::Mmio { .. } => None,
            QemuMemoryData::Zero { .. } | QemuMemoryData::File { .. } => Some((
                unsafe { qemu_sys::memory_region_get_ram_ptr(region) },
                qemu_memory_map.size(),
            )),
        };

        Self {
            qemu_memory_map,
            _callback_handler: callback_handler,
            region,
            raw_pointer,
        }
    }

    unsafe fn pointer(&self) -> Option<&mut [u8]> {
        self.raw_pointer.map(|(ram_ptr, size)| unsafe {
            slice::from_raw_parts_mut(ram_ptr as _, size as usize)
        })
    }

    fn memory_blocks(&self) -> impl Iterator<Item = MemoryBlock> {
        let aliases = self.inner().alias();
        let mut blocks = Vec::with_capacity(1 + aliases.len());

        if let Some(pointer) = unsafe { self.pointer() } {
            let readonly = self.inner().readonly();

            blocks.push(MemoryBlock {
                readonly,
                start: self.qemu_memory_map.start(),
                data: pointer,
            });

            for alias in aliases {
                let offset = alias.base_offset() as usize;
                let size = alias.size() as usize;
                blocks.push(MemoryBlock {
                    readonly,
                    start: alias.start(),
                    data: &pointer[offset..(offset + size)],
                })
            }
        }

        blocks.into_iter()
    }

    pub(crate) fn inner(&self) -> &QemuMemoryMap {
        &self.qemu_memory_map
    }

    fn overlaps_with(&self, other: &Self) -> bool {
        self.qemu_memory_map.contains_map(&other.qemu_memory_map)
            || other.qemu_memory_map.contains_map(&self.qemu_memory_map)
    }

    pub(crate) fn memory_region_raw(
        &mut self,
    ) -> (&mut qemu_sys::MemoryRegion, PageAddress, Address, &mut [u8]) {
        let region = unsafe { &mut *self.region };
        let start = self.qemu_memory_map.start();
        let size = self.qemu_memory_map.size();
        let pointer = unsafe { self.pointer() }.unwrap();

        debug_assert_eq!(start, region.addr as Address);
        debug_assert_eq!(size, region.size as USize);
        debug_assert_eq!(pointer.as_ptr(), unsafe {
            qemu_sys::memory_region_get_ram_ptr(region) as _
        });

        (region, PageAddress::new(start), size, pointer)
    }
}

impl fmt::Debug for Memory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Memory")
            .field("qemu_memory_map", &self.qemu_memory_map)
            .field("region", &self.region)
            .field("raw_pointer", &self.raw_pointer)
            .finish()
    }
}

impl<'a> MemoryBlock<'a> {
    pub fn contains(&self, address: Address) -> bool {
        crate::memory::contains(self.start, self.data.len() as USize, address)
    }
}
