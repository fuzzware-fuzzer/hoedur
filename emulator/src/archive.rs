use std::{
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use archive::{
    tar::{deserialize_yml, deserialize_yml_zst, read_string, TarEntry},
    Entry, EntryKind,
};
use common::FxHashMap;
use enum_kinds::EnumKind;
use modeling::mmio::Mmio;

#[derive(Debug, EnumKind)]
#[enum_kind(EmulatorEntryKind)]
pub enum EmulatorEntry {
    TargetConfig(PathBuf),
    MmioModels(Vec<Mmio>),
    Commandline(Vec<String>),
    FileMap(FxHashMap<PathBuf, PathBuf>),
    ConfigFile(PathBuf, Vec<u8>),
}

impl<'a, R: Read> EntryKind<'a, R> for EmulatorEntryKind {
    fn from_path(path: &Path) -> Option<Self> {
        Some(if path == Path::new("config/target-config.txt") {
            Self::TargetConfig
        } else if path == Path::new("config/models.yml.zst") {
            Self::MmioModels
        } else if path == Path::new("config/cmdline.yml") {
            Self::Commandline
        } else if path == Path::new("config/filemap.yml") {
            Self::FileMap
        } else if path.starts_with("config/file-storage/") {
            Self::ConfigFile
        } else {
            return None;
        })
    }
}

impl<'a, R: Read> Entry<'a, R> for EmulatorEntryKind {
    type Type = EmulatorEntry;

    fn parse(&self, entry: &mut TarEntry<'a, R>) -> Result<Self::Type> {
        Ok(match self {
            Self::TargetConfig => Self::Type::TargetConfig(read_string(entry).map(PathBuf::from)?),
            Self::MmioModels => Self::Type::MmioModels(deserialize_yml_zst(entry)?),
            Self::Commandline => Self::Type::Commandline(deserialize_yml(entry)?),
            Self::FileMap => Self::Type::FileMap(deserialize_yml(entry)?),
            Self::ConfigFile => {
                // read file
                let mut content = Vec::with_capacity(entry.header().size().unwrap_or(0) as usize);
                entry
                    .read_to_end(&mut content)
                    .context("Failed to read config file")?;

                // get file path
                let path = entry.header().path().context("Failed to read path")?;

                Self::Type::ConfigFile(path.to_string_lossy().to_string().into(), content)
            }
        })
    }
}
