use std::{ffi::OsStr, io::Read, path::Path};

use anyhow::{Context, Result};
use archive::{
    tar::{deserialize_yml, write_serialized_yml, TarEntry},
    ArchiveBuilder, Entry, EntryKind,
};
use common::time::epoch;
use enum_kinds::EnumKind;

use crate::mmio::Mmio;

#[derive(Debug, EnumKind)]
#[enum_kind(ModelingEntryKind)]
pub enum ModelingEntry {
    MmioModel(Mmio),
}

impl<'a, R: Read> EntryKind<'a, R> for ModelingEntryKind {
    fn from_path(path: &Path) -> Option<Self> {
        Some(
            if path.starts_with("config/models/")
                && path.extension().and_then(OsStr::to_str) == Some("yml")
            {
                Self::MmioModel
            } else {
                return None;
            },
        )
    }
}

impl<'a, R: Read> Entry<'a, R> for ModelingEntryKind {
    type Type = ModelingEntry;

    fn parse(&self, entry: &mut TarEntry<'a, R>) -> Result<Self::Type> {
        Ok(match self {
            Self::MmioModel => Self::Type::MmioModel(deserialize_yml(entry)?),
        })
    }
}

pub fn write_to_archive(archive: &ArchiveBuilder, model: &Mmio) -> Result<()> {
    write_serialized_yml(
        &mut archive.borrow_mut(),
        &format!("config/models/{}.yml", model.context),
        epoch()?,
        model,
    )
    .context("Failed to write model to archive")
}
