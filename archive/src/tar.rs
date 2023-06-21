use anyhow::{Context, Result};
use semver::Version;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::{Read, Write};

use common::{time::Epoch, GIT_VERSION};

pub const VERSION: Version = Version::new(0, 10, 0);
pub const MIN_VERSION: Version = Version::new(0, 7, 0);

pub use tar::{Builder, Entry as TarEntry};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaInfo {
    version: Version,
    timestamp: Epoch,
    #[serde(default = "unknown_version")]
    git_version: String,
}

impl MetaInfo {
    pub fn new(timestamp: Epoch) -> Self {
        Self {
            version: VERSION,
            timestamp,
            git_version: GIT_VERSION.to_owned(),
        }
    }

    pub fn version(&self) -> &Version {
        &self.version
    }
    pub fn timestamp(&self) -> Epoch {
        self.timestamp
    }
    pub fn git_version(&self) -> &str {
        &self.git_version
    }
}

pub fn unknown_version() -> String {
    "unknown".into()
}

pub fn read_tar<R: Read, F: FnMut(&mut tar::Entry<R>) -> Result<()>>(
    reader: R,
    mut f: F,
) -> Result<()> {
    let mut archive = tar::Archive::new(reader);

    for entry in archive.entries().context("Failed to iterate tar entries")? {
        let mut entry = entry.context("Failed to get entry")?;

        f(&mut entry)?;
    }

    Ok(())
}

pub fn create_tar<W: Write>(writer: W, mtime: Epoch, raw_archive: bool) -> Result<Builder<W>> {
    let mut archive = tar::Builder::new(writer);
    archive.mode(tar::HeaderMode::Deterministic);

    if !raw_archive {
        // write meta info
        write_serialized_yml(&mut archive, "meta.yml", mtime, &MetaInfo::new(mtime))
            .context("Failed to serialize meta info")?;

        // write static config
        write_file(
            &mut archive,
            "config/config.rs",
            mtime,
            common::CONFIG.as_bytes(),
        )
        .context("Failed to write static config file")?;
    }

    Ok(archive)
}

pub fn write_tar<W: Write, F: FnOnce(&mut tar::Builder<W>) -> Result<()>>(
    writer: W,
    mtime: Epoch,
    f: F,
) -> Result<()> {
    let mut archive = create_tar(writer, mtime, true)?;

    f(&mut archive)?;

    archive
        .into_inner()
        .context("Failed to write tar archive")?
        .flush()
        .context("Failed to flush writer")
}

fn header(filename: &str, size: u64, mtime: u64) -> Result<tar::Header, anyhow::Error> {
    let mut header = tar::Header::new_gnu();
    header
        .set_path(filename)
        .context("Failed to set file path")?;
    header.set_size(size);
    header.set_mtime(mtime);
    header.set_mode(0o664);
    header.set_cksum();

    Ok(header)
}

fn pad_zero<W: Write>(dst: &mut W, size: u64) -> Result<()> {
    // Pad with zeros if necessary.
    let buf = [0; 512];
    let remaining = 512 - (size % 512);

    if remaining < 512 {
        dst.write_all(&buf[..remaining as usize])
            .context("Failed to zero pad file")
    } else {
        Ok(())
    }
}

pub fn write_file_raw<W: Write, F: FnOnce(&mut W) -> Result<()>>(
    archive: &mut tar::Builder<W>,
    filename: &str,
    size: u64,
    mtime: Epoch,
    writer: F,
) -> Result<()> {
    let dst = archive.get_mut();

    // create + write header
    dst.write_all(header(filename, size, mtime)?.as_bytes())?;

    // call writer
    writer(dst).context("Failed to write file content")?;

    // pad file
    pad_zero(dst, size)?;

    Ok(())
}

pub fn write_serialized_yml<W: Write, S: Serialize>(
    archive: &mut tar::Builder<W>,
    filename: &str,
    mtime: Epoch,
    content: &S,
) -> Result<()> {
    // TODO: get serialzed size and use writer (see bincode)
    write_file(
        archive,
        filename,
        mtime,
        serde_yaml::to_string(content)
            .context("Failed to serialize file content")?
            .as_bytes(),
    )
}

pub fn write_serialized<W: Write, S: Serialize>(
    archive: &mut tar::Builder<W>,
    filename: &str,
    mtime: Epoch,
    content: &S,
) -> Result<()> {
    let size = bincode::serialized_size(content)?;

    write_file_raw(archive, filename, size, mtime, |dst| {
        bincode::serialize_into(dst, content).context("Failed to serialize file content")
    })
}

pub fn write_file<W: Write>(
    archive: &mut tar::Builder<W>,
    filename: &str,
    mtime: Epoch,
    content: &[u8],
) -> Result<()> {
    let header = header(filename, content.len() as u64, mtime)?;

    archive
        .append(&header, content)
        .context("Failed to append to tar archive")?;

    Ok(())
}

pub fn read_meta<R: Read>(entry: &mut tar::Entry<R>) -> Result<MetaInfo> {
    let meta: MetaInfo =
        serde_yaml::from_reader(entry).context("Failed to deserialize meta info")?;

    if meta.version < MIN_VERSION {
        anyhow::bail!(
            "Invalid input file version. Expected at least version '{}'.",
            MIN_VERSION
        );
    }

    Ok(meta)
}

pub fn read_string<R: Read>(mut entry: R) -> Result<String> {
    let mut content = String::new();
    entry
        .read_to_string(&mut content)
        .context("Failed to text file")?;

    Ok(content)
}

pub fn deserialize<R: Read, T: DeserializeOwned>(entry: R) -> Result<T> {
    bincode::deserialize_from(entry).context("Failed to deserialize")
}

pub fn deserialize_yml<R: Read, T: DeserializeOwned>(entry: R) -> Result<T> {
    serde_yaml::from_reader(entry).context("Failed to deserialize")
}

pub fn deserialize_yml_zst<R: Read, T: DeserializeOwned>(entry: R) -> Result<T> {
    serde_yaml::from_reader(zstd::Decoder::new(entry).context("Failed to create zstd decoder")?)
        .context("Failed to deserialize")
}
