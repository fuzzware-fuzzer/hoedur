mod archive;
mod corpus;
mod corpus_archive;
pub mod coverage;
mod dict;
mod fuzzer;
mod mutation;
pub mod statistics;
mod stream;
mod stream_distribution;

pub use crate::{
    archive::{FuzzerEntry, FuzzerEntryKind},
    corpus::{InputCategory, InputResult},
    corpus_archive::{
        write_input_file, CorpusEntry, CorpusEntryKind, CorpusInputFile, IntoInputFileIter,
    },
    fuzzer::Fuzzer,
};
