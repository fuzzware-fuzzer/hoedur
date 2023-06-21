use std::{
    borrow::Cow,
    fmt::Debug,
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use hashbrown::hash_map::RawEntryMut;

use crate::{
    fs::{bufreader, normalize_path, relative_path},
    FxHashMap,
};

pub struct FileStorage {
    allow_fs: bool,
    target_config: PathBuf,
    working_directory: PathBuf,
    files: FxHashMap<PathBuf, Vec<u8>>,
}

impl Debug for FileStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileStorage")
            .field("allow_fs", &self.allow_fs)
            .field("target_config", &self.target_config)
            .field(
                "files",
                &self
                    .files
                    .iter()
                    .map(|(path, content)| (path.as_path(), content.len()))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl FileStorage {
    pub fn new(target_config: PathBuf) -> Result<Self> {
        let mut file_storage = Self::with_fs(target_config.clone(), true);

        // read target config file
        file_storage
            .read_inner(&target_config)
            .context("Failed to read target config")?;

        Ok(file_storage)
    }

    pub fn with_files(target_config: PathBuf, files: FxHashMap<PathBuf, Vec<u8>>) -> Result<Self> {
        let mut file_storage = Self::with_fs(target_config, false);

        // make paths relative
        file_storage.files = files
            .into_iter()
            .map(|(path, content)| {
                file_storage
                    .normalize_path(&path)
                    .map(|path| (path, content))
            })
            .collect::<Result<_>>()
            .context("Failed to make paths relative to working directory")?;
        log::debug!(
            "loaded files: {:#?}",
            file_storage.files.keys().collect::<Vec<_>>()
        );

        Ok(file_storage)
    }

    fn with_fs(target_config: PathBuf, allow_fs: bool) -> Self {
        // current work dir (config file parent)
        let working_directory = match target_config.parent() {
            Some(parent) => parent.into(),
            None => PathBuf::from("."),
        };

        Self {
            allow_fs,
            target_config,
            working_directory,
            files: FxHashMap::default(),
        }
    }

    pub fn read(&mut self, path: &Path) -> Result<()> {
        // only when filesystem access is allowed
        if self.allow_fs {
            self.read_inner(path)
        } else {
            Ok(())
        }
    }

    pub fn read_from_fs(&mut self, path: &Path) -> Result<()> {
        self.read_inner(path)
    }

    pub fn get(&self, path: &Path) -> Result<&[u8]> {
        // normalize path
        let normalized_path = self.normalize_path(path)?;
        log::debug!("get: normalized_path = {:#?}", normalized_path);

        self.files
            .get(&normalized_path)
            .map(Vec::as_slice)
            .with_context(|| format!("File {path:?} missing in file storage"))
    }

    pub fn target_config(&self) -> &Path {
        &self.target_config
    }

    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    pub fn files(&self) -> impl Iterator<Item = (&Path, &[u8])> {
        self.files
            .iter()
            .map(|(path, content)| (path.as_path(), content.as_slice()))
    }

    fn read_inner(&mut self, path: &Path) -> Result<()> {
        // normalize path
        let normalized_path = self.normalize_path(path)?;
        log::debug!("read: normalized_path = {:#?}", normalized_path);

        match self.files.raw_entry_mut().from_key(&normalized_path) {
            RawEntryMut::Occupied(_) => {}
            RawEntryMut::Vacant(entry) => {
                // read file
                let file_path = if normalized_path.is_absolute() || normalized_path.is_file() {
                    Cow::Borrowed(&normalized_path)
                } else {
                    Cow::Owned(self.working_directory.join(&normalized_path))
                };
                let mut content = vec![];
                bufreader(&file_path)?
                    .read_to_end(&mut content)
                    .with_context(|| format!("Failed to read file {file_path:?}"))?;

                entry.insert(normalized_path, content);
            }
        }

        Ok(())
    }

    fn normalize_path(&self, path: &Path) -> Result<PathBuf> {
        if path.is_absolute() {
            relative_path(path, &self.working_directory)
        } else {
            Ok(normalize_path(path))
        }
    }
}
