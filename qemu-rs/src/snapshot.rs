use std::{
    convert::TryInto,
    fmt,
    hash::BuildHasherDefault,
    ops::{Add, Deref},
    ptr,
    rc::Rc,
    sync::atomic::{self, AtomicUsize},
};

use anyhow::{Context, Result};
use common::{hashbrown::hash_map::Entry, FxHashMap, FxHashSet, FxHasher};
use qemu_sys::PAGE_SIZE;

use crate::{
    coverage::{get_last_location, set_last_location, RawBitmap},
    memory::{QemuMemoryData, QemuMemoryMap},
    qcontrol::{cpu, cpu_mut},
    qcontrol_mut, Address, QemuStateControl, USize,
};

#[cfg(feature = "arm")]
pub type CpuState = qemu_sys::CPUARMState;

static NEXT_SNAPSHOT_ID: AtomicUsize = AtomicUsize::new(0);
static mut LAST_MEMORY_SNAPSHOT: Option<Rc<MemorySnapshot>> = None;

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub(crate) struct PageAddress(Address);
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
struct PageOffset(USize);

impl PageAddress {
    pub(crate) fn new(page: Address) -> Self {
        Self(page)
    }
}

impl Add<PageOffset> for PageAddress {
    type Output = PageAddress;

    fn add(self, rhs: PageOffset) -> Self::Output {
        PageAddress(self.0 + rhs.0)
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct MemorySnapshotId(usize);

impl Deref for MemorySnapshotId {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Default for MemorySnapshotId {
    fn default() -> Self {
        Self::next()
    }
}

impl MemorySnapshotId {
    pub fn next() -> Self {
        Self(NEXT_SNAPSHOT_ID.fetch_add(1, atomic::Ordering::Relaxed))
    }
}

#[cfg(debug_assertions)]
fn verify_page_size() -> Result<()> {
    let page_size = unsafe { qemu_sys::qemu_target_page_size() } as usize;

    if page_size != PAGE_SIZE {
        anyhow::bail!(
            "Invalid target page size {:#x?}, expected {:#x?}",
            page_size,
            PAGE_SIZE
        );
    } else {
        Ok(())
    }
}

#[cfg(not(debug_assertions))]
fn verify_page_size() -> Result<()> {
    Ok(())
}

macro_rules! page {
    ($pointer:expr, $offset:expr) => {{
        let offset = $offset.0 as usize;

        // verify offset is at page start
        debug_assert!(offset % PAGE_SIZE == 0);

        // page start + end
        let start = offset;
        let end = start + PAGE_SIZE as usize;

        // get slice to page
        &mut $pointer[start..end]
    }};
}

fn last_memory_snapshot() -> Result<Rc<MemorySnapshot>, anyhow::Error> {
    verify_page_size()?;

    unsafe {
        LAST_MEMORY_SNAPSHOT
            .take()
            .context("last memory snapshot missing")
    }
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    cpu: CpuSnapshot,
    bitmap: Rc<RawBitmap>,
    memory: Rc<MemorySnapshot>,
    last_location: u64,
}

#[derive(Debug, Clone)]
struct CpuSnapshot {
    cpu_state: CpuState,

    #[cfg(feature = "arm")]
    arm_state: crate::arm::snapshot::ArmCpuSnapshot,
    #[cfg(feature = "arm")]
    nvic_state: Option<crate::arm::snapshot::NvicSnapshot>,
}

#[derive(Clone, Debug)]
pub struct MmioRewound {
    cflags_next_tb: u32,
    last_location: u64,
}

#[derive(Clone, Debug, Default)]
pub struct MemorySnapshot {
    id: MemorySnapshotId,
    regions: FxHashMap<PageAddress, MemoryRegionSnapshot>,
}

#[derive(Debug, Clone)]
struct MemoryRegionSnapshot {
    start_address: PageAddress,
    dirty_pages: FxHashMap<PageOffset, DirtyPage<PAGE_SIZE>>,
    dirty_bitmap: FxHashMap<PageOffset, MemorySnapshotId>,
}

#[derive(Clone)]
struct DirtyPage<const PAGE_SIZE: usize>(Rc<[u8; PAGE_SIZE]>);

impl<const PAGE_SIZE: usize> DirtyPage<PAGE_SIZE> {
    fn from_slice(page: &[u8]) -> Self {
        DirtyPage(Rc::new(page.try_into().unwrap()))
    }
}

impl<const PAGE_SIZE: usize> Deref for DirtyPage<PAGE_SIZE> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl<const PAGE_SIZE: usize> fmt::Debug for DirtyPage<PAGE_SIZE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DirtyPage")
    }
}

struct DirtyMemory<'a> {
    start_address: PageAddress,
    dirty_pages: Vec<PageOffset>,
    pointer: &'a mut [u8],
}

impl<'a> fmt::Debug for DirtyMemory<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirtyMemory")
            .field("start_address", &self.start_address)
            .field("dirty_pages", &self.dirty_pages)
            .field("pointer", &self.pointer.as_ptr())
            .finish()
    }
}

impl MemorySnapshot {
    pub(crate) fn init(memory_maps: &mut [QemuMemoryMap]) {
        // snapshot id
        let id = MemorySnapshotId::next();

        // TODO: make memory_maps readonly ref

        let mut regions = FxHashMap::default();
        for memory_map in memory_maps {
            if let QemuMemoryData::File { data, readonly } = &mut memory_map.data {
                if *readonly {
                    continue;
                }

                let mut dirty_pages = vec![];
                for offset in (0..memory_map.size).step_by(PAGE_SIZE) {
                    dirty_pages.push(PageOffset(offset));
                }

                // add dirty memory region
                let start_address = PageAddress(memory_map.start);
                regions.insert(
                    start_address,
                    MemoryRegionSnapshot::create(
                        id,
                        &mut DirtyMemory {
                            start_address,
                            dirty_pages,
                            pointer: data,
                        },
                    ),
                );
            }
        }

        unsafe {
            LAST_MEMORY_SNAPSHOT = Some(Rc::new(Self { id, regions }));
        }
    }

    pub fn create() -> Result<Rc<Self>> {
        verify_page_size()?;

        // snapshot id
        let id = MemorySnapshotId::next();

        // collect new dirty pages
        let regions = get_dirty_memory(qcontrol_mut())
            .iter_mut()
            .map(|dirty_memory| {
                (
                    dirty_memory.start_address,
                    MemoryRegionSnapshot::create(id, dirty_memory),
                )
            })
            .collect();

        // merge snapshot with previous
        let mut memory = last_memory_snapshot()?;
        let memory_ptr = Rc::make_mut(&mut memory);
        memory_ptr.merge(regions);
        memory_ptr.id = id;

        // keep snapshot for future merges
        unsafe {
            LAST_MEMORY_SNAPSHOT = Some(memory.clone());
        }

        log::trace!("memory snapshot = {:#x?}", memory);

        Ok(memory)
    }

    pub fn restore(self: Rc<Self>) -> Result<()> {
        let qemu = qcontrol_mut();
        let last_snapshot = last_memory_snapshot()?;

        // restore currently dirty memory from snapshot
        let mut dirty_memory_regions = get_dirty_memory(qemu);
        for dirty_memoy in &mut dirty_memory_regions {
            let memory_snapshot = self
                .regions
                .get(&dirty_memoy.start_address)
                .context("Missing dirty memory region in snapshot")?;

            dirty_memoy.restore_from(memory_snapshot);
        }

        // only look into dirty bitmap if we restore another snapshot
        if self.id != last_snapshot.id {
            // set of already restored dirty pages
            let already_restored: FxHashSet<(PageAddress, PageOffset)> = dirty_memory_regions
                .iter()
                .flat_map(|dirty_memoy| {
                    dirty_memoy
                        .dirty_pages
                        .iter()
                        .copied()
                        .map(move |offset| (dirty_memoy.start_address, offset))
                })
                .collect();
            log::trace!("already_restored = {:#x?}", already_restored);

            // R/W memory regions (RAM)
            for memory in qemu
                .memory_mut()
                .iter_mut()
                .filter(|memory| memory.inner().dirty_map())
            {
                let (_, start, _, pointer) = memory.memory_region_raw();

                // last snapshot regions
                if let Some(last_memory_snapshot) = last_snapshot.regions.get(&start) {
                    // region to restore
                    let memory_snapshot = self
                        .regions
                        .get(&start)
                        .context("memory region missing in snapshot")?;

                    // restore dirty pages present in last snapshot
                    for (offset, id) in &last_memory_snapshot.dirty_bitmap {
                        // skip already restored pages
                        if already_restored.contains(&(last_memory_snapshot.start_address, *offset))
                        {
                            continue;
                        }

                        // only restore dirty pages (snapshot id in dirty bitmap changed)
                        if memory_snapshot.dirty_bitmap.get(offset) != Some(id) {
                            memory_snapshot.restore_page(pointer, offset);
                        }
                    }
                }
            }
        }

        // restore last snapsot for future merges
        unsafe {
            LAST_MEMORY_SNAPSHOT = Some(self);
        }

        Ok(())
    }

    pub fn set_dirty_bitmap(&self, qemu: &mut QemuStateControl) -> Result<()> {
        // get dirty pages
        let dirty_pages: Vec<_> = self
            .regions
            .values()
            .flat_map(|memory| memory.dirty_pages())
            .collect();

        // restore dirty bitmap from snapshot
        verify_page_size()?;
        set_dirty_memory(qemu, &dirty_pages);

        Ok(())
    }

    /// Merge two snapshots.
    /// `new_regions` have precedence over `self.regions`.
    fn merge(&mut self, new_regions: FxHashMap<PageAddress, MemoryRegionSnapshot>) {
        // merge dirty regions
        for (start_address, new_region) in new_regions {
            match self.regions.entry(start_address) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().merge(new_region);
                }
                Entry::Vacant(entry) => {
                    entry.insert(new_region);
                }
            }
        }
    }
}

impl Snapshot {
    pub fn create() -> Result<Self> {
        Ok(Self {
            cpu: CpuSnapshot::create().context("create CPU snapshot")?,
            bitmap: Rc::new(RawBitmap::create_snapshot()),
            memory: MemorySnapshot::create().context("create memory snapshot")?,
            last_location: get_last_location(),
        })
    }

    pub fn restore(&self) -> Result<()> {
        self.memory
            .clone()
            .restore()
            .context("restore memory snapshot")?;
        self.cpu.restore().context("restore CPU snapshot")?;
        self.bitmap.restore_snapshot();
        set_last_location(self.last_location);

        Ok(())
    }
}

impl MmioRewound {
    pub fn create() -> Self {
        Self {
            cflags_next_tb: cpu().parent_obj.cflags_next_tb,
            last_location: get_last_location(),
        }
    }

    pub fn restore(&self) {
        cpu_mut().parent_obj.cflags_next_tb = self.cflags_next_tb;
        set_last_location(self.last_location);
    }
}

impl CpuSnapshot {
    fn create() -> Result<Self> {
        let cpu = cpu();

        Ok(Self {
            cpu_state: create_cpu_snaphsot(&cpu.env),

            #[cfg(feature = "arm")]
            arm_state: crate::arm::snapshot::ArmCpuSnapshot::create(cpu),
            #[cfg(feature = "arm")]
            nvic_state: crate::qcontrol()
                .board()?
                .nvic()
                .map(crate::arm::snapshot::NvicSnapshot::create),
        })
    }

    fn restore(&self) -> Result<()> {
        let cpu = cpu_mut();

        restore_cpu(&mut cpu.env, &self.cpu_state);

        #[cfg(feature = "arm")]
        self.arm_state.restore(cpu);
        #[cfg(feature = "arm")]
        if let Some(nvic_state) = &self.nvic_state {
            nvic_state
                .restore(
                    qcontrol_mut()
                        .board_mut()?
                        .nvic_mut()
                        .context("NVIC state missing")?,
                )
                .context("restore NVIC state")?;
        }

        Ok(())
    }
}

fn create_cpu_snaphsot(cpu: &CpuState) -> CpuState {
    let mut snapshot = CpuState::default();
    copy_cpu_state(&mut snapshot, cpu);
    snapshot
}

fn restore_cpu(cpu: &mut CpuState, snapshot: &CpuState) {
    // verify break-/watchpoint pointers are the same
    #[cfg(feature = "arm")]
    {
        debug_assert_eq!(cpu.cpu_breakpoint, snapshot.cpu_breakpoint);
        debug_assert_eq!(cpu.cpu_watchpoint, snapshot.cpu_watchpoint);
    }

    copy_cpu_state(cpu, snapshot);
}

fn copy_cpu_state(dst: &mut CpuState, src: &CpuState) {
    // verify pointers are not equal
    assert_ne!(dst as *const _, src as *const _);

    // get size of fields to reset
    let reset_size = cpu_reset_size(src);

    // copy cpu state
    unsafe {
        ptr::copy_nonoverlapping(
            src as *const _ as *const u8,
            dst as *mut _ as *mut u8,
            reset_size,
        )
    };
}

fn cpu_reset_size(cpu: &CpuState) -> usize {
    let end_offset = unsafe {
        ((&cpu.end_reset_fields) as *const _ as *const u8).offset_from(cpu as *const _ as *const u8)
    };
    debug_assert!(end_offset > 0);

    end_offset as usize
}

impl MemoryRegionSnapshot {
    fn create(id: MemorySnapshotId, dirty_memory: &mut DirtyMemory) -> Self {
        // get dirty bitmap with id
        let dirty_bitmap = dirty_memory
            .dirty_pages
            .iter()
            .copied()
            .map(|offset| (offset, id))
            .collect();

        // snapshot dirty pages
        let mut dirty_pages = FxHashMap::with_capacity_and_hasher(
            dirty_memory.dirty_pages.len(),
            BuildHasherDefault::<FxHasher>::default(),
        );
        for offset in &mut dirty_memory.dirty_pages {
            // get slice to page
            let page = &*page!(dirty_memory.pointer, offset);

            // copy dirty page
            dirty_pages.insert(*offset, DirtyPage::from_slice(page));
        }

        MemoryRegionSnapshot {
            start_address: dirty_memory.start_address,
            dirty_pages,
            dirty_bitmap,
        }
    }

    fn dirty_pages(&self) -> Vec<PageAddress> {
        self.dirty_pages
            .keys()
            .map(|offset| self.start_address + *offset)
            .collect()
    }

    /// Merge two memory region snapshots.
    /// Pages of `new_snapshot` have precedence over `self`.
    fn merge(&mut self, new_snapshot: MemoryRegionSnapshot) {
        // verify we are the same memory region
        debug_assert_eq!(self.start_address, new_snapshot.start_address);

        // update/insert dirty pages/bitmap from new snapshot
        self.dirty_pages.extend(new_snapshot.dirty_pages);
        self.dirty_bitmap.extend(new_snapshot.dirty_bitmap);
    }

    fn restore_page(&self, pointer: &mut [u8], offset: &PageOffset) {
        log::trace!(
            "restore_page: start_address = {:x?}, offset = {:x?}",
            self.start_address,
            offset
        );

        // get mut slice to page
        let page = page!(pointer, offset);

        // restore data
        if let Some(data) = self.dirty_pages.get(offset) {
            // use data from snapshot
            page.copy_from_slice(data)
        } else {
            // fallback to zero
            page.fill(0)
        }
    }
}

impl<'a> DirtyMemory<'a> {
    fn restore_from(&mut self, snapshot: &MemoryRegionSnapshot) {
        for offset in self.dirty_pages.iter() {
            snapshot.restore_page(self.pointer, offset);
        }
    }
}

fn set_dirty_memory(qemu: &mut QemuStateControl, dirty_pages: &[PageAddress]) {
    use qemu_sys::memory_region_set_dirty;

    // R/W memory regions (RAM)
    for memory in qemu
        .memory_mut()
        .iter_mut()
        .filter(|memory| memory.inner().dirty_map())
    {
        let (region, start, size, _) = memory.memory_region_raw();

        for offset in (0..size).step_by(PAGE_SIZE) {
            // was page dirty?
            let dirty = dirty_pages.contains(&(start + PageOffset(offset)));
            if dirty {
                unsafe { memory_region_set_dirty(region, offset as u64, PAGE_SIZE as u64) };
            }
        }
    }
}

fn get_dirty_memory(qemu: &mut QemuStateControl) -> Vec<DirtyMemory> {
    use qemu_sys::memory_region_snapshot_and_clear_dirty;

    // R/W memory regions (RAM)
    let mut dirty_memory = vec![];
    for memory in qemu
        .memory_mut()
        .iter_mut()
        .filter(|memory| memory.inner().dirty_map())
    {
        let (region, start, size, pointer) = memory.memory_region_raw();

        // NOTE: this is our bottleneck
        let snapshot_ptr = unsafe {
            memory_region_snapshot_and_clear_dirty(
                region,
                0,
                size as u64,
                qemu_sys::DIRTY_MEMORY_VGA,
            )
        };
        let snapshot = unsafe { snapshot_ptr.as_mut() }.unwrap();

        // bitset count
        let pages = size as usize / PAGE_SIZE;
        let bitset_size = u64::BITS as usize;
        let last_bits = pages % bitset_size;
        let bitsets = pages / bitset_size + usize::from(last_bits != 0);

        // dirty bitset
        let dirty = unsafe { snapshot.dirty.as_mut_slice(bitsets) };

        // clear invalid bits when unaligned
        if last_bits > 0 {
            if let Some(last_bitset) = dirty.last_mut() {
                *last_bitset &= u64::MAX >> (bitset_size - last_bits);
            }
        }

        // optimized implementation of `memory_region_snapshot_get_dirty` for high(er) performance
        let mut dirty_pages = vec![];
        for (index, mut bitset) in dirty.iter().copied().enumerate() {
            while bitset != 0 {
                let lowest_bit_index = bitset.trailing_zeros() as usize;
                let page = (index * bitset_size) + lowest_bit_index;
                let offset = page * PAGE_SIZE;
                dirty_pages.push(PageOffset(offset as USize));

                // toggle lowest bit with magic
                bitset ^= (bitset as i64 & (bitset as i64).wrapping_neg()) as u64;
            }
        }

        // free dirty bitmap snapshot
        let _ = snapshot;
        unsafe { glib_sys::g_free(snapshot_ptr as _) };

        // add dirty memory region
        dirty_memory.push(DirtyMemory {
            start_address: start,
            dirty_pages,
            pointer,
        });
    }

    log::trace!("dirty_memory = {:#x?}", dirty_memory);

    dirty_memory
}
