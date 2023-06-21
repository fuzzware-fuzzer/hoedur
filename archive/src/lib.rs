use std::{
    cell::{Ref, RefCell, RefMut},
    ffi::OsStr,
    fmt,
    fs::{self, File},
    hash::{Hash, Hasher},
    io::{BufWriter, Read, Seek, Write},
    marker::PhantomData,
    path::Path,
    sync::Arc,
};

use ::common::{file_storage::FileStorage, fs::encoder, time::epoch, FxHashMap, FxHasher};
use ::tar::{Builder, Entries, Entry as TarEntry};
use anyhow::{Context, Result};
use fslock::LockFile;
use zstd::stream::AutoFinishEncoder;

pub mod common;
pub mod tar;

use crate::tar::{create_tar, write_file, write_serialized_yml};

pub use crate::tar::{read_meta, read_string, MetaInfo};
pub use ::tar::{Archive as TarArchive, Header};

const ARCHIVE_EXT: &str = "corpus.tar.zst";

pub type ArchiveWriter = AutoFinishEncoder<'static, BufWriter<File>>;

#[repr(transparent)]
#[derive(Clone)]
pub struct ArchiveBuilder(pub Arc<RefCell<Builder<ArchiveWriter>>>);
pub struct Archive<R: Read>(TarArchive<R>);

impl fmt::Debug for ArchiveBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArchiveBuilder").finish()
    }
}

impl From<Builder<ArchiveWriter>> for ArchiveBuilder {
    fn from(builder: Builder<ArchiveWriter>) -> Self {
        Self(Arc::new(RefCell::new(builder)))
    }
}

impl ArchiveBuilder {
    pub fn borrow(&self) -> Ref<Builder<ArchiveWriter>> {
        self.0.borrow()
    }

    pub fn borrow_mut(&self) -> RefMut<Builder<ArchiveWriter>> {
        self.0.borrow_mut()
    }
}

impl<R: Read> Archive<R> {
    pub fn from_reader(reader: R) -> Self {
        Self(TarArchive::new(reader))
    }

    pub fn iter<'a, K: Entry<'a, R> + EntryKind<'a, R>>(
        &'a mut self,
    ) -> Result<ArchiveIterator<'a, R, K>> {
        ArchiveIterator::from_archive(&mut self.0)
    }
}

impl<R: Read + Seek> Archive<R> {
    pub fn iter_seek<'a, K: Entry<'a, R> + EntryKind<'a, R>>(
        &'a mut self,
    ) -> Result<ArchiveIterator<'a, R, K>> {
        ArchiveIterator::from_archive_with_seek(&mut self.0)
    }
}

pub trait EntryKind<'a, R: Read>: fmt::Debug + Sized {
    fn from_entry(entry: &TarEntry<'a, R>) -> Result<Option<Self>> {
        entry
            .path()
            .context("Failed to get entry path")
            .map(|path| Self::from_path(path.as_ref()))
    }

    fn from_path(path: &Path) -> Option<Self>;
}
pub trait Entry<'a, R: Read> {
    type Type;

    fn parse(&self, entry: &mut TarEntry<'a, R>) -> Result<Self::Type>;
}

pub struct ArchiveIterator<'a, R: Read, K: Entry<'a, R> + EntryKind<'a, R>> {
    entries: Entries<'a, R>,
    kind: PhantomData<K>,
}

impl<'a, R: Read, K: Entry<'a, R> + EntryKind<'a, R>> ArchiveIterator<'a, R, K> {
    pub fn from_archive(archive: &'a mut TarArchive<R>) -> Result<Self> {
        archive
            .entries()
            .context("Failed to open corpus archive")
            .map(|entries| Self {
                entries,
                kind: PhantomData::default(),
            })
    }

    pub fn meta(mut self) -> Option<MetaInfo> {
        self.entries.find_map(|entry| {
            match entry
                .context("Failed to read tar entry")
                .and_then(|mut entry| {
                    let path = entry.path().context("Failed to get entry path")?;

                    // parse meta info
                    if path == Path::new("meta.yml") {
                        read_meta(&mut entry)
                            .context("Failed to parse meta info")
                            .map(Some)
                    } else {
                        Ok(None)
                    }
                }) {
                Ok(meta) => meta,
                Err(err) => {
                    log::error!("Failed to process archive entry: {:?}", err);
                    None
                }
            }
        })
    }
}
impl<'a, R: Read + Seek, K: Entry<'a, R> + EntryKind<'a, R>> ArchiveIterator<'a, R, K> {
    pub fn from_archive_with_seek(archive: &'a mut TarArchive<R>) -> Result<Self> {
        archive
            .entries_with_seek()
            .context("Failed to open corpus archive in seek mode")
            .map(|entries| Self {
                entries,
                kind: PhantomData::default(),
            })
    }
}

pub struct ArchiveEntry<'a, R: Read, K: Entry<'a, R> + EntryKind<'a, R>> {
    kind: Option<K>,
    entry: TarEntry<'a, R>,
}

impl<'a, R: Read, K: Entry<'a, R> + EntryKind<'a, R>> Iterator for ArchiveIterator<'a, R, K> {
    type Item = Result<ArchiveEntry<'a, R, K>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.entries.next().map(|entry| {
            let entry = entry.context("Failed to read tar entry")?;
            let kind = K::from_entry(&entry).context("Failed to parse entry kind")?;

            Ok(ArchiveEntry { kind, entry })
        })
    }
}

impl<'a, R: Read, K: Entry<'a, R> + EntryKind<'a, R>> ArchiveEntry<'a, R, K> {
    pub fn header(&mut self) -> &Header {
        self.entry.header()
    }

    pub fn raw_entry(&mut self) -> &mut TarEntry<'a, R> {
        &mut self.entry
    }
}

impl<'a, R: Read, K: Entry<'a, R> + EntryKind<'a, R> + Copy> ArchiveEntry<'a, R, K> {
    pub fn kind(&self) -> Option<K> {
        self.kind
    }

    pub fn parse_entry(&mut self) -> Option<Result<K::Type>> {
        self.kind.map(|kind| {
            kind.parse(&mut self.entry).with_context(|| {
                format!(
                    "Failed to parse {:?} as {:?}",
                    self.entry.path(),
                    self.kind()
                )
            })
        })
    }
}

pub fn create_archive(
    archive_dir: &Path,
    name: &str,
    overwrite: bool,
    raw_archive: bool,
) -> Result<Builder<ArchiveWriter>> {
    // name and create archive dir
    let archive_path = archive_dir.join(format!("{name}.{ARCHIVE_EXT}"));
    log::info!("Creating archive dir at {:?} ...", archive_dir);
    fs::create_dir_all(archive_dir).context("Failed to create archive dir")?;

    // lock archive dir
    let lockfile_path = archive_dir.join("corpus.lock");
    let mut lockfile =
        LockFile::open(&lockfile_path).context(format!("open lockfile {lockfile_path:?}"))?;
    if !lockfile.try_lock_with_pid()? {
        log::info!("Waiting for lock on archive dir ...");
        lockfile.lock_with_pid()?;
    }
    log::debug!("lock for archive dir acquired");

    // move old archive
    if !overwrite && archive_path.is_file() {
        log::warn!("Archive {:?} already exists", archive_path);

        for i in 1.. {
            let path = archive_dir.join(format!("{name}.{i}.{ARCHIVE_EXT}"));

            if !path.exists() {
                log::info!(
                    "Moving old archive from {:?} to {:?} ...",
                    archive_path,
                    path
                );
                fs::rename(&archive_path, path).context("Failed to move old archive")?;
                break;
            }
        }
    }

    // create archive file
    create_tar(
        encoder(&archive_path)
            .with_context(|| format!("Failed to create archive file at {archive_path:?}"))?,
        epoch()?,
        raw_archive,
    )
}

pub fn write_config<W: Write>(archive: &mut Builder<W>) -> Result<()> {
    let mtime = epoch()?;

    // write command line args
    write_serialized_yml(
        archive,
        "config/cmdline.yml",
        mtime,
        &std::env::args().collect::<Vec<_>>(),
    )
    .context("write commandline arguments")?;

    // write hoedur config
    write_file(
        archive,
        "config/config.rs",
        mtime,
        ::common::CONFIG.as_bytes(),
    )
    .context("write hoedur config")
}

pub fn write_file_storage<W: Write>(
    archive: &mut Builder<W>,
    file_storage: &FileStorage,
) -> Result<()> {
    let mtime = epoch()?;

    // write target config symlink
    write_file(
        archive,
        "config/target-config.txt",
        mtime,
        file_storage.target_config().to_string_lossy().as_bytes(),
    )
    .context("write target config path")?;

    // write file storage
    let mut filemap = FxHashMap::default();
    for (path, content) in file_storage.files() {
        // hash file
        let mut hasher = FxHasher::default();
        content.hash(&mut hasher);
        let hash = hasher.finish();

        // create unique filename
        let filename = format!(
            "config/file-storage/{:016x?}/{}",
            hash,
            path.file_name()
                .map(OsStr::to_string_lossy)
                .unwrap_or_else(|| "noname".into())
        );

        write_file(archive, &filename, mtime, content)
            .with_context(|| format!("write config {path:?}"))?;

        filemap.insert(path, filename);
    }

    // write filename to real path mapping
    write_serialized_yml(archive, "config/filemap.yml", mtime, &filemap)
        .context("write config filemap")
}
