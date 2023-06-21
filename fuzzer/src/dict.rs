use std::{
    ascii::escape_default,
    fmt::{self, Write},
};

use common::random::FastRand;
use rand_distr::{Distribution, Uniform};

const MIN_LEN: usize = 4;
const MAX_LEN: usize = 64;

#[derive(Debug, Default)]
pub struct Dictionary {
    entries: Vec<Entry>,
    distribution: Option<Uniform<usize>>,
    // TODO: maybe add energy for good strings
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry(Vec<u8>);

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self
            .0
            .iter()
            .copied()
            .flat_map(|byte| char::from_u32(byte as u32))
        {
            f.write_char(c)?;
        }

        Ok(())
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_char('"')?;

        for c in self
            .0
            .iter()
            .copied()
            .flat_map(escape_default)
            .flat_map(|byte| char::from_u32(byte as u32))
        {
            f.write_char(c)?;
        }

        f.write_char('"')
    }
}

impl Dictionary {
    pub fn scan_memory_block(&mut self, memory_block: &[u8]) {
        let mut buffer = vec![];
        let mut heuristic_bad = 0;
        let mut heuristic_good = 0;
        let mut valid = false;

        // collect ascii "good" strings
        for (idx, byte) in memory_block.iter().copied().enumerate() {
            // is valid ascii (printable + newline + tab)
            let valid_byte = matches!(byte, b'\r' | b'\n' | b'\t' | 0x20..=0x7e);
            if valid_byte {
                // heuristic for "good" chars
                if byte.is_ascii_alphanumeric()
                    || matches!(byte, b' ' | b'_' | b'-' | b'=' | b'/' | b'.' | b'\'' | b'"')
                {
                    heuristic_good += 1;
                } else if buffer.last() == Some(&b'\r') && byte == b'\n' {
                    // special case: count '\r\n' as one bad char (newline)
                } else {
                    heuristic_bad += 1;
                }

                buffer.push(byte);
                valid = true;
            }

            // add (valid) strings after last byte / invalid next byte
            let last_byte = idx == memory_block.len() - 1;
            if valid && (!valid_byte || last_byte) {
                let entry = Entry(buffer);
                log::trace!("found printable ASCII string: {:?}", entry);

                // string within length limits
                if entry.0.len() >= MIN_LEN && entry.0.len() <= MAX_LEN {
                    // string has >=75% "good" chars
                    if heuristic_bad * 3 < heuristic_good {
                        log::debug!("add dict entry: {:?}", entry);
                        self.entries.push(entry);
                    }
                }

                // reset buffer
                buffer = vec![];
                heuristic_bad = 0;
                heuristic_good = 0;
                valid = false;
            }
        }

        // remove duplicates
        self.entries.sort_unstable();
        self.entries.dedup();

        // update random distribution
        self.distribution = (!self.entries.is_empty()).then(|| Uniform::new(0, self.entries.len()));
    }

    pub fn random_entry(&self) -> Option<&Entry> {
        self.distribution
            .map(|dist| dist.sample(&mut FastRand))
            .and_then(|idx| self.entries.get(idx))
    }
}

impl AsRef<[u8]> for Entry {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
