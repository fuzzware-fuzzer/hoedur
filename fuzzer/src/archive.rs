use std::{io::Read, path::Path};

use anyhow::{Context, Result};
use archive::{
    tar::{deserialize, TarEntry},
    Entry, EntryKind,
};
use enum_kinds::EnumKind;

use crate::statistics::{ExecutionsHistory, InputSizeHistory};

#[derive(Debug, EnumKind)]
#[enum_kind(FuzzerEntryKind)]
pub enum FuzzerEntry {
    Seed(u64),
    ExecutionsHistory(Vec<ExecutionsHistory>),
    InputSizeHistory(Vec<InputSizeHistory>),
}

impl<'a, R: Read> EntryKind<'a, R> for FuzzerEntryKind {
    fn from_path(path: &Path) -> Option<Self> {
        Some(if path == Path::new("config/seed.bin") {
            Self::Seed
        } else if path == Path::new("statistics/executions.bin") {
            Self::ExecutionsHistory
        } else if path == Path::new("statistics/input-size.bin") {
            Self::InputSizeHistory
        } else {
            return None;
        })
    }
}

impl<'a, R: Read> Entry<'a, R> for FuzzerEntryKind {
    type Type = FuzzerEntry;

    fn parse(&self, entry: &mut TarEntry<'a, R>) -> Result<Self::Type> {
        Ok(match self {
            Self::Seed => {
                let mut buf = [0u8; 8];
                entry.read_exact(&mut buf).context("Failed to read seed")?;
                Self::Type::Seed(u64::from_be_bytes(buf))
            }
            Self::ExecutionsHistory => Self::Type::ExecutionsHistory(deserialize(entry)?),
            Self::InputSizeHistory => Self::Type::InputSizeHistory(deserialize(entry)?),
        })
    }
}
