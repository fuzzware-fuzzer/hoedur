use std::{io::Read, path::Path};

use ::tar::Entry as TarEntry;
use anyhow::Result;
use enum_kinds::EnumKind;

use crate::{Entry, EntryKind};

pub use crate::tar::{read_meta, read_string, MetaInfo};
pub use ::tar::{Archive as TarArchive, Header};

#[derive(Debug, EnumKind)]
#[enum_kind(CommonEntryKind)]
pub enum CommonEntry {
    Meta(MetaInfo),
    StaticConfig(StaticConfig),
}

impl<'a, R: Read> EntryKind<'a, R> for CommonEntryKind {
    fn from_path(path: &Path) -> Option<Self> {
        Some(if path == Path::new("meta.yml") {
            Self::Meta
        } else if path == Path::new("config/config.rs") {
            Self::StaticConfig
        } else {
            return None;
        })
    }
}

impl<'a, R: Read> Entry<'a, R> for CommonEntryKind {
    type Type = CommonEntry;

    fn parse(&self, entry: &mut TarEntry<'a, R>) -> Result<Self::Type> {
        Ok(match self {
            Self::Meta => Self::Type::Meta(read_meta(entry)?),
            Self::StaticConfig => Self::Type::StaticConfig(read_string(entry).map(StaticConfig)?),
        })
    }
}

#[derive(Debug)]
pub struct StaticConfig(pub String);

impl StaticConfig {
    pub fn verify(&self) -> bool {
        let diff = self.0 != common::CONFIG;

        if diff {
            log::warn!("Corpus archive was created with a different config.");
            log::debug!("Current config:\n{}", common::CONFIG);
            log::debug!("Corpus archive config:\n{}", self.0);
        }

        !diff
    }
}
