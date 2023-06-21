use std::{
    fs::{self, File},
    io::{BufReader, BufWriter},
    path::{Component, Path, PathBuf},
    time::SystemTime,
};

use anyhow::{Context, Result};
use pathdiff::diff_paths;
use zstd::stream::AutoFinishEncoder;

pub fn find_files(
    path: &Path,
    prefix: Option<&str>,
    postfix: Option<&str>,
) -> Result<Vec<PathBuf>> {
    let mut files = vec![];

    for entry in path.read_dir().context("read_dir call failed")? {
        let entry = entry.context("invalid dir entry")?;

        // filter files
        if !entry.path().is_file() {
            log::debug!("{:?} not a file", entry);
            continue;
        }

        // filter by filename prefix/postfix
        if prefix.is_some() || postfix.is_some() {
            let filename = entry.file_name();
            let filename = filename.to_string_lossy();

            // filter by prefix
            if let Some(prefix) = prefix {
                if !filename.starts_with(prefix) {
                    continue;
                }
            }

            // filter by postfix
            if let Some(postfix) = postfix {
                if !filename.ends_with(postfix) {
                    continue;
                }
            }
        }

        // add to files list
        files.push(entry.path());
    }

    Ok(files)
}

// https://github.com/rust-lang/cargo/blob/fede83ccf973457de319ba6fa0e36ead454d2e20/src/cargo/util/paths.rs#L61
pub fn normalize_path(path: &Path) -> PathBuf {
    let mut components = path.components().peekable();
    let mut ret = if let Some(c @ Component::Prefix(..)) = components.peek().cloned() {
        components.next();
        PathBuf::from(c.as_os_str())
    } else {
        PathBuf::new()
    };

    for component in components {
        match component {
            Component::Prefix(..) => unreachable!(),
            Component::RootDir => {
                ret.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                ret.pop();
            }
            Component::Normal(c) => {
                ret.push(c);
            }
        }
    }
    ret
}

pub fn relative_path(path: &Path, working_directory: &Path) -> Result<PathBuf> {
    diff_paths(normalize_path(path), normalize_path(working_directory)).with_context(|| {
        format!("Failed to make path {path:?} relative to working directory {working_directory:?}")
    })
}

pub fn modify_time(path: &Path) -> Result<u64> {
    let timestamp = fs::metadata(path)
        .context("Failed to get input file metadata")?
        .modified()
        .context("Failed to get mtime from metadata")?
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("invalid system time")?
        .as_secs();

    Ok(timestamp)
}

pub fn bufreader(path: &Path) -> Result<BufReader<File>> {
    File::open(path)
        .with_context(|| format!("Failed to open file {path:?}"))
        .map(BufReader::new)
}

pub fn decoder(path: &Path) -> Result<zstd::Decoder<BufReader<File>>> {
    zstd::Decoder::new(File::open(path).with_context(|| format!("Failed to open file {path:?}"))?)
        .context("Failed to create zstd decoder")
}

pub fn bufwriter(path: &Path) -> Result<BufWriter<File>> {
    File::create(path)
        .with_context(|| format!("Failed to create file {path:?}"))
        .map(BufWriter::new)
}

pub fn encoder(path: &Path) -> Result<AutoFinishEncoder<'static, BufWriter<File>>> {
    zstd::Encoder::new(bufwriter(path)?, 0)
        .context("Failed to create zstd encoder")
        .map(|encoder| encoder.auto_finish())
}

pub fn decoder_slice(data: &[u8]) -> Result<zstd::Decoder<BufReader<&[u8]>>> {
    zstd::Decoder::new(data).context("Failed to create zstd decoder")
}
