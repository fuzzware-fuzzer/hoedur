use std::path::Path;

use anyhow::Result;
use archive::ArchiveBuilder;

use crate::cli;

pub fn create_archive(name: &str, archive_dir: &Path) -> Result<ArchiveBuilder> {
    archive::create_archive(archive_dir, name, false, false).map(ArchiveBuilder::from)
}

pub fn opt_archive(archive: &cli::Archive) -> Option<&Path> {
    archive
        .write_archive
        .then_some(&archive.archive_dir)
        .map(|archive_dir| archive_dir.archive_dir.as_ref())
}
