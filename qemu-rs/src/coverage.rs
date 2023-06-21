use std::{
    fmt, fs,
    mem::MaybeUninit,
    ops::BitXor,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

use anyhow::{Context, Result};
use common::config::{
    emulator::ENABLE_HIT_COUNT,
    fuzzer::{CoverageBitmapEntry, COVERAGE_BITMAP_SIZE},
};

static mut COVERAGE_BITMAP: MaybeUninit<RawBitmap> = MaybeUninit::uninit();
static INIT_DONE: AtomicBool = AtomicBool::new(false);

pub const HASH_KEY: u64 = 0x517cc1b727220a95;
static mut LAST_LOCATION: u64 = 0;

pub type RawEntry = CoverageBitmapEntry;

#[derive(Clone)]
pub struct RawBitmap(Vec<RawEntry>);

impl RawBitmap {
    pub fn read_from(path: &Path) -> Result<Self> {
        fs::read(path)
            .with_context(|| format!("Failed to read raw bitmap from {path:?}"))
            .map(|unaligned| {
                let (prefix, data, postfix) = unsafe { unaligned.align_to::<RawEntry>() };
                assert!(prefix.is_empty());
                assert!(postfix.is_empty());
                data.to_vec()
            })
            .map(RawBitmap)
    }

    pub fn write_to(&self, path: &Path) -> Result<()> {
        let (prefix, data, postfix) = unsafe { self.as_ref().align_to::<u8>() };
        assert!(prefix.is_empty());
        assert!(postfix.is_empty());

        fs::write(path, data).with_context(|| format!("Failed to write bitmap to {path:?}"))
    }

    pub fn index(&self, edge: u64) -> usize {
        edge as usize & (self.0.len() - 1)
    }

    fn add(&mut self, edge: u64) {
        let index = self.index(edge);
        let entry = unsafe { self.0.get_unchecked_mut(index) };
        *entry = (*entry).saturating_add(1);
    }

    fn set(&mut self, edge: u64) {
        let index = self.index(edge);
        let entry = unsafe { self.0.get_unchecked_mut(index) };
        *entry = 1;
    }

    pub(crate) fn create_snapshot() -> Self {
        get_coverage_bitmap().clone()
    }

    pub(crate) fn restore_snapshot(&self) {
        get_coverage_bitmap_mut().0.copy_from_slice(&self.0)
    }
}

impl AsRef<[RawEntry]> for RawBitmap {
    fn as_ref(&self) -> &[RawEntry] {
        &self.0
    }
}

impl AsMut<[RawEntry]> for RawBitmap {
    fn as_mut(&mut self) -> &mut [RawEntry] {
        &mut self.0
    }
}

impl fmt::Debug for RawBitmap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RawBitmap([RawEntry; {}])", self.0.len())
    }
}

pub(crate) fn init_done() -> bool {
    INIT_DONE.load(Ordering::SeqCst)
}

pub fn init_coverage_bitmap() {
    set_coverage_bitmap_vec(vec![0; COVERAGE_BITMAP_SIZE]);
}

pub unsafe fn set_coverage_bitmap(bitmap_ptr: *mut RawEntry, len: usize) {
    set_coverage_bitmap_vec(Vec::from_raw_parts(bitmap_ptr, len, len))
}

fn set_coverage_bitmap_vec(bitmap: Vec<RawEntry>) {
    log::trace!(
        "set_coverage_bitmap: bitmap ptr = {:p}, size = {:#x?}",
        bitmap.as_ptr(),
        bitmap.len()
    );
    assert!(!INIT_DONE.swap(true, Ordering::SeqCst));
    assert_eq!(bitmap.len() % usize::BITS as usize, 0);
    assert_eq!(bitmap.len(), bitmap.capacity());

    unsafe {
        COVERAGE_BITMAP.write(RawBitmap(bitmap));
    }
}

pub fn get_coverage_bitmap() -> &'static RawBitmap {
    debug_assert!(init_done());

    unsafe { COVERAGE_BITMAP.assume_init_ref() }
}

pub fn get_coverage_bitmap_mut() -> &'static mut RawBitmap {
    debug_assert!(init_done());

    unsafe { COVERAGE_BITMAP.assume_init_mut() }
}

pub fn get_last_location() -> u64 {
    let last_location = unsafe { LAST_LOCATION };
    log::trace!("get_last_location() = {:#x?})", last_location);

    last_location
}

pub fn set_last_location(last_location: u64) {
    log::trace!("set_last_location(last_location = {:#x?})", last_location);

    unsafe {
        LAST_LOCATION = last_location;
    }
}

pub fn add_basic_block(pc: u64) {
    // calculate edge
    let current_location = pc.wrapping_mul(HASH_KEY);
    let edge = current_location.bitxor(unsafe { LAST_LOCATION });

    // update coverage bitmap
    if ENABLE_HIT_COUNT {
        get_coverage_bitmap_mut().add(edge);
    } else {
        get_coverage_bitmap_mut().set(edge);
    }

    // update last lcoation
    unsafe { LAST_LOCATION = current_location.rotate_left(5) }
}
