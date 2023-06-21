use std::{
    ops::{BitXor, Deref, Shr},
    usize,
};

use emulator::{
    coverage::{RawBitmap, RawEntry, HASH_KEY},
    Address,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Serialize, Deserialize)]
pub struct Feature(usize);

const HIT_BUCKET_BITS: usize = hit_bucket_bits();

const fn hit_bucket_bits() -> usize {
    let mut i = 0;

    assert!(RawEntry::BITS < u8::MAX as u32);
    while RawEntry::BITS >= (1 << i) {
        i += 1;
    }

    i
}

impl Feature {
    pub(crate) fn new(index: usize, hit_bucket: u8) -> Self {
        debug_assert!(index <= (usize::MAX >> HIT_BUCKET_BITS));
        Self(index << HIT_BUCKET_BITS | hit_bucket as usize)
    }

    pub fn edge(self) -> Edge {
        Edge::new(self.0 >> HIT_BUCKET_BITS)
    }

    pub fn hit_bucket(self) -> u8 {
        (self.0 & 0xf) as u8
    }

    pub fn as_raw(self) -> usize {
        self.0
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct CoverageBitmap(Vec<Feature>);

impl CoverageBitmap {
    pub fn features(&self) -> &[Feature] {
        &self.0
    }
}

pub fn edge_bitmap(raw_bitmap: &RawBitmap) -> CoverageBitmap {
    let raw_bitmap: &[RawEntry] = raw_bitmap.as_ref();
    let mut features = Vec::with_capacity(raw_bitmap.len());

    let (prefix, qwords, postfix) = unsafe { raw_bitmap.align_to::<usize>() };
    debug_assert!(prefix.is_empty());
    debug_assert!(postfix.is_empty());

    const USIZE_BYTES: usize = (usize::BITS / RawEntry::BITS) as usize;
    const BYTE_MASK: usize = (RawEntry::MAX as usize) << (usize::BITS - RawEntry::BITS);
    const HIT_BUCKET_MASK: usize = (RawEntry::BITS - 1) as usize;

    let mut feature_idx = 0;
    for (qidx, qword) in qwords.iter().enumerate() {
        let mut qword = *qword;

        while qword != 0 {
            let zeros = qword.leading_zeros() as usize;
            let first_bit = zeros & !HIT_BUCKET_MASK;
            let index = (qidx * USIZE_BYTES) + USIZE_BYTES - 1 - first_bit.shr(3);
            let hit_bucket = (RawEntry::BITS as usize) - (zeros & HIT_BUCKET_MASK);

            unsafe {
                *features.get_unchecked_mut(feature_idx) = Feature::new(index, hit_bucket as u8)
            };
            feature_idx += 1;

            qword &= (!BYTE_MASK).rotate_right(first_bit as u32);
        }
    }

    unsafe { features.set_len(feature_idx) };

    CoverageBitmap(features)
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Edge(usize);

impl Edge {
    pub(crate) fn new(index: usize) -> Self {
        Self(index)
    }

    pub fn from_index(bitmap: &RawBitmap, index: usize) -> Self {
        debug_assert!(index < bitmap.as_ref().len());
        Self::new(index)
    }

    pub fn from_locations(bitmap: &RawBitmap, last: Address, current: Address) -> Self {
        let last_location = (last as u64).wrapping_mul(HASH_KEY).rotate_left(5);
        let current_location = (current as u64).wrapping_mul(HASH_KEY);
        let edge = current_location.bitxor(last_location);
        let index = bitmap.index(edge);

        Self(index)
    }
}

impl Deref for Edge {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
