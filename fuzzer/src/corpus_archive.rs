use std::{
    io::{Read, Write},
    path::Path,
};

use anyhow::{Context, Result};
use archive::{
    common::{CommonEntry, CommonEntryKind},
    tar::{self, deserialize, write_file_raw, TarEntry},
    ArchiveEntry, ArchiveIterator, Entry, EntryKind,
};
use common::time::Epoch;
use emulator::archive::{EmulatorEntry, EmulatorEntryKind};
use modeling::{
    archive::{ModelingEntry, ModelingEntryKind},
    hardware::WriteTo,
    input::InputFile,
};

use crate::{
    archive::{FuzzerEntry, FuzzerEntryKind},
    InputCategory, InputResult,
};

#[derive(Debug, Clone, Copy)]
pub enum CorpusEntryKind {
    Common(CommonEntryKind),
    Emulator(EmulatorEntryKind),
    Modeling(ModelingEntryKind),
    Fuzzer(FuzzerEntryKind),
    InputFile(InputCategory),
}

#[derive(Debug)]
pub enum CorpusEntry {
    Common(CommonEntry),
    Emulator(EmulatorEntry),
    Modeling(ModelingEntry),
    Fuzzer(FuzzerEntry),
    InputFile {
        category: InputCategory,
        input: InputFile,
    },
}

impl<'a, R: Read> EntryKind<'a, R> for CorpusEntryKind {
    fn from_path(path: &Path) -> Option<Self> {
        <CommonEntryKind as EntryKind<R>>::from_path(path)
            .map(Self::Common)
            .or_else(|| <EmulatorEntryKind as EntryKind<R>>::from_path(path).map(Self::Emulator))
            .or_else(|| <ModelingEntryKind as EntryKind<R>>::from_path(path).map(Self::Modeling))
            .or_else(|| <FuzzerEntryKind as EntryKind<R>>::from_path(path).map(Self::Fuzzer))
            .or_else(|| {
                let is_input = path
                    .file_name()
                    .map(|file_name| file_name.to_string_lossy().starts_with("input-"))
                    .unwrap_or(false);

                is_input.then(|| {
                    CorpusEntryKind::InputFile(if path.starts_with("input/") {
                        InputCategory::Input
                    } else if path.starts_with("crash/") {
                        InputCategory::Crash
                    } else if path.starts_with("exit/") {
                        InputCategory::Exit
                    } else if path.starts_with("timeout/") {
                        InputCategory::Timeout
                    } else {
                        log::warn!("Unknown input category: {:?}", path);
                        InputCategory::Invalid
                    })
                })
            })
    }
}

impl<'a, R: Read> Entry<'a, R> for CorpusEntryKind {
    type Type = CorpusEntry;

    fn parse(&self, entry: &mut TarEntry<'a, R>) -> Result<Self::Type> {
        match self {
            CorpusEntryKind::Common(kind) => kind.parse(entry).map(CorpusEntry::Common),
            CorpusEntryKind::Emulator(kind) => kind.parse(entry).map(CorpusEntry::Emulator),
            CorpusEntryKind::Modeling(kind) => kind.parse(entry).map(CorpusEntry::Modeling),
            CorpusEntryKind::Fuzzer(kind) => kind.parse(entry).map(CorpusEntry::Fuzzer),
            CorpusEntryKind::InputFile(category) => Ok(Self::Type::InputFile {
                category: *category,
                input: deserialize(entry)?,
            }),
        }
    }
}

pub struct InputFileIterator<'a, R: Read> {
    inner: ArchiveIterator<'a, R, CorpusEntryKind>,
}

pub trait IntoInputFileIter<'a, R: Read> {
    fn input_files(self) -> InputFileIterator<'a, R>;
}

impl<'a, R: Read> IntoInputFileIter<'a, R> for ArchiveIterator<'a, R, CorpusEntryKind> {
    fn input_files(self) -> InputFileIterator<'a, R> {
        InputFileIterator { inner: self }
    }
}

pub struct CorpusInputFile {
    pub timestamp: Epoch,
    pub category: InputCategory,
    pub input: InputFile,
}

impl<'a, R: Read> Iterator for InputFileIterator<'a, R> {
    type Item = Result<CorpusInputFile>;

    fn next(&mut self) -> Option<Self::Item> {
        for result in self.inner.by_ref() {
            let input = match result {
                Ok(entry) => corpus_input_file(entry),
                Err(err) => return Some(Err(err)),
            };

            if let Some(result) = input {
                return Some(result);
            }
        }

        None
    }
}

fn corpus_input_file<R: Read>(
    mut entry: ArchiveEntry<R, CorpusEntryKind>,
) -> Option<Result<CorpusInputFile>> {
    matches!(entry.kind(), Some(CorpusEntryKind::InputFile(_)))
        .then(|| {
            entry.parse_entry().map(|result| {
                result.and_then(|corpus_entry| match corpus_entry {
                    CorpusEntry::InputFile { category, input } => Ok(CorpusInputFile {
                        timestamp: entry.header().mtime().with_context(|| {
                            format!(
                                "Failed to read mtime header for entry {:?}",
                                entry.header().path()
                            )
                        })?,
                        category,
                        input,
                    }),
                    _ => unreachable!(),
                })
            })
        })
        .flatten()
}

pub fn write_input_file<W: Write>(
    archive: &mut tar::Builder<W>,
    result: &InputResult,
) -> Result<()> {
    write_file_raw(
        archive,
        &format!(
            "{}/{}",
            result.category().as_str(),
            result.file().filename()
        ),
        result.file().write_size()?,
        result.timestamp(),
        |writer| result.file().write_to(writer),
    )
    .context("add input file to corpus archive")
}
