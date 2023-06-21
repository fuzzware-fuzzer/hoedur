use rand_core::{impls, Error, RngCore};
use rustc_hash::FxHasher;
use std::hash::{Hash, Hasher};

pub struct FastRand;

impl RngCore for FastRand {
    fn next_u32(&mut self) -> u32 {
        fastrand::u32(..)
    }

    fn next_u64(&mut self) -> u64 {
        fastrand::u64(..)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_next(self, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

pub trait DeriveRandomSeed: Hash {
    fn derive<H: Hash>(&self, value: &H) -> u64 {
        let mut hasher = FxHasher::default();
        self.hash(&mut hasher);
        value.hash(&mut hasher);
        hasher.finish()
    }
}

impl DeriveRandomSeed for u64 {}
