use std::{cmp, fmt, iter, ops::Range};

use anyhow::{Context, Result};
use common::{config::mutation::*, hashbrown::hash_map::Entry, random::FastRand, FxHashMap};
use enum_dispatch::enum_dispatch;
use enum_index::IndexEnum;
use enum_index_derive::IndexEnum;
use enum_kinds::EnumKind;
use modeling::{
    input::value::{InputValue, InputValueType},
    input::{
        stream::{InputStream, Stream},
        InputContext, InputFile,
    },
};
use once_cell::sync::OnceCell;
use rand_distr::{Distribution, WeightedAliasIndex};
use serde::{Deserialize, Serialize};
use variant_count::VariantCount;

use crate::{
    dict,
    fuzzer::InputFork,
    stream::{ChronoStream, StreamIndex},
    stream_distribution::StreamRandomDistribution,
    InputResult,
};

static DISTRIBUTION_BLOCK_SIZE: OnceCell<WeightedAliasIndex<usize>> = OnceCell::new();

#[derive(Debug, Clone)]
pub struct MutationLog {
    pub mode: MutationMode,
    pub distribution: Option<StreamRandomDistribution>,
    pub mutation: Mutation,
}

#[derive(Debug, EnumKind)]
#[enum_kind(
    MutationMode,
    derive(Hash, PartialOrd, Ord, IndexEnum, VariantCount, Serialize, Deserialize)
)]
pub enum MutationContext {
    Stream(StreamRandomDistribution),
    Mono { context: InputContext },
}

impl MutationContext {
    pub fn distribution(&self) -> Option<StreamRandomDistribution> {
        match self {
            Self::Stream(distribution) => Some(*distribution),
            _ => None,
        }
    }
}

#[enum_dispatch(Mutate, Variant)]
#[derive(Debug, Clone, EnumKind)]
#[enum_kind(
    MutatorKind,
    derive(Hash, PartialOrd, Ord, IndexEnum, VariantCount, Serialize, Deserialize)
)]
pub enum Mutator {
    EraseValues,
    InsertValue,
    InsertRepeatedValue,
    ChangeValue,
    OffsetValue,
    InvertValueBit,
    ShuffleValues,
    CopyValuePart,
    CrossOverValuePart,
    Splice,
    ChronoEraseValues,
    ChronoCopyValuePart,
    Dictionary,
    InterestingValue,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MutatorVariant {
    None,
    Insert(bool),
    Offset {
        overflow: Overflow,
        invert_endianness: bool,
    },
}

impl fmt::Debug for MutatorVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Insert(insert) => {
                if *insert {
                    write!(f, "Insert")
                } else {
                    write!(f, "Overwrite")
                }
            }
            Self::Offset {
                overflow,
                invert_endianness,
            } => match (overflow, invert_endianness) {
                (Overflow::None, false) => write!(f, "Default"),
                (Overflow::None, true) => write!(f, "InvEndian"),
                (_, false) => f.debug_tuple("Overflow").field(overflow).finish(),
                (_, true) => {
                    f.debug_tuple("Overflow").field(overflow).finish()?;
                    write!(f, "+InvEndian")
                }
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct Mutation {
    target: StreamIndex,
    mutator: Mutator,
}

impl Mutation {
    pub fn new(target: StreamIndex, mutator: Mutator) -> Self {
        Self { target, mutator }
    }

    pub fn create<'a, F: Fn() -> Option<&'a InputResult>>(
        mutator: MutatorKind,
        target: StreamIndex,
        input: &InputFork,
        dictionary: &dict::Dictionary,
        random_input: F,
    ) -> Result<Option<Mutation>> {
        // get input stream
        let stream = || {
            input
                .file()
                .input_streams()
                .get(&target.context)
                .context("Failed to get input stream.")
        };

        // search for cross over input
        let search_cross_over = |chrono| {
            for _ in 0..MAX_CROSS_OVER_RETRY {
                match random_input() {
                    Some(input) => {
                        let is_non_empty = if chrono {
                            input.chrono_stream().contains(&target.context)
                        } else {
                            input.file().input_streams().contains_key(&target.context)
                        };

                        // return input when none empty target stream is found
                        if is_non_empty {
                            return Some(input);
                        }
                    }
                    // early exit when no input is available
                    None => return None,
                }
            }

            None
        };

        let mutator: Mutator = match mutator {
            MutatorKind::EraseValues => EraseValues::new(stream()?.len())?.into(),
            MutatorKind::InsertValue => InsertValue::new(stream()?.value_type()).into(),
            MutatorKind::InsertRepeatedValue => {
                InsertRepeatedValue::new(stream()?.value_type())?.into()
            }
            MutatorKind::ChangeValue => ChangeValue::new(stream()?.value_type()).into(),
            MutatorKind::OffsetValue => OffsetValue::new(stream()?.value_type()).into(),
            MutatorKind::InvertValueBit => InvertValueBit::new(stream()?.value_type()).into(),
            MutatorKind::ShuffleValues => ShuffleValues::new().into(),
            MutatorKind::CopyValuePart => CopyValuePart::new(stream()?.len())?.into(),
            MutatorKind::CrossOverValuePart => {
                if let Some(cross_over) = search_cross_over(false)
                    .map(InputResult::file)
                    .map(InputFile::input_streams)
                    .and_then(|input_streams| input_streams.get(&target.context))
                {
                    CrossOverValuePart::new(cross_over)?.into()
                } else {
                    return Ok(None);
                }
            }
            MutatorKind::Splice => match search_cross_over(true) {
                Some(cross_over) => Splice::new(cross_over, &target.context)?.into(),
                None => return Ok(None),
            },
            MutatorKind::ChronoEraseValues => ChronoEraseValues::new(input.file().len())?.into(),
            MutatorKind::ChronoCopyValuePart => {
                ChronoCopyValuePart::new(input.file().len())?.into()
            }
            MutatorKind::Dictionary => {
                if let Some(dict) = Dictionary::new(stream()?.value_type(), dictionary) {
                    dict.into()
                } else {
                    return Ok(None);
                }
            }
            MutatorKind::InterestingValue => InterestingValue::new(stream()?.value_type())?.into(),
        };

        Ok(Some(Mutation::new(target, mutator)))
    }
}

impl Mutation {
    pub fn apply(&self, input: &mut InputFork) -> Result<bool> {
        if self.mutator.is_valid_and_effective(input, &self.target) {
            self.mutator.mutate(input, &self.target).with_context(|| {
                log::debug!("{:#?}", self);
                format!("Failed to apply {:?} mutation", self.mutator())
            })?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn mutator(&self) -> MutatorKind {
        MutatorKind::from(&self.mutator)
    }

    pub fn mutator_variant(&self) -> MutatorVariant {
        self.mutator.variant()
    }

    pub fn target(&self) -> &StreamIndex {
        &self.target
    }
}

#[enum_dispatch]
pub trait Variant {
    fn variant(&self) -> MutatorVariant {
        MutatorVariant::None
    }
}

#[enum_dispatch]
pub trait Mutate {
    fn mutate(&self, input: &mut InputFork, target: &StreamIndex) -> Result<()>;
    fn is_valid_and_effective(&self, input: &InputFork, target: &StreamIndex) -> bool;
}

pub trait MutateStream {
    fn mutate(&self, stream: &mut Vec<InputValue>, index: usize);

    fn is_valid(&self, stream: &[InputValue], index: usize) -> bool {
        index < stream.len()
    }

    fn is_effective(&self, _stream: &[InputValue], _index: usize) -> bool {
        true
    }
}

impl<T: MutateStream> Mutate for T {
    fn mutate(&self, input: &mut InputFork, target: &StreamIndex) -> Result<()> {
        input
            .file_mut()
            .input_streams_mut()
            .get_mut(&target.context)
            .context("Failed to get input stream.")
            .map(|stream| {
                debug_assert!(target.index <= stream.len());
                MutateStream::mutate(self, stream.as_mut(), target.index)
            })
    }

    fn is_valid_and_effective(&self, input: &InputFork, target: &StreamIndex) -> bool {
        input
            .file()
            .input_streams()
            .get(&target.context)
            .map(|stream| {
                MutateStream::is_valid(self, stream.as_ref(), target.index)
                    && MutateStream::is_effective(self, stream.as_ref(), target.index)
            })
            .unwrap_or(false)
    }
}

fn random_block_len(min_len: usize, max_len: usize) -> Result<usize> {
    // init block size distribution
    let distribution_block_size = DISTRIBUTION_BLOCK_SIZE
        .get_or_try_init(|| {
            WeightedAliasIndex::new(BLOCK_SIZES_DISTRIBUTION.to_vec())
                .context("Failed to create a weighted block size distribution.")
        })
        .context("Failed to initialize global block size distribution")?;

    // get upper block size limit (2^N)
    let block_len_pow2 = BLOCK_SIZES_POW2[distribution_block_size.sample(&mut FastRand)];

    // limit min_len by max_len
    let min_len = min_len.min(max_len);

    // max block size (2^N), limited by max_len
    let block_len_max = (1 << block_len_pow2).clamp(min_len, max_len);

    // get random block size length within bounds
    Ok(fastrand::usize(min_len..=block_len_max))
}

#[derive(PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct Random {
    count: usize,
}

impl Random {
    pub fn new() -> Self {
        Self {
            count: 1 << fastrand::usize(RANDOM_COUNT_INPUT_RANGE_POW2),
        }
    }

    pub fn mutate(&self, input: &mut InputFile) {
        input.set_random_count(self.count);
    }

    pub fn is_valid_and_effective(&self, input: &InputFile) -> bool {
        input.random_count().is_none()
    }
}

impl Default for Random {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Random {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Random({})", self.count)
    }
}

#[derive(Debug, Clone)]
pub struct EraseValues {
    count: usize,
}

impl EraseValues {
    fn new(len: usize) -> Result<Self> {
        let count = random_block_len(1, len)?;
        Ok(Self { count })
    }
}

impl Variant for EraseValues {}

impl MutateStream for EraseValues {
    fn mutate(&self, stream: &mut Vec<InputValue>, index: usize) {
        let end = cmp::min(index + self.count, stream.len());
        stream.splice(index..end, iter::empty());
    }

    fn is_effective(&self, stream: &[InputValue], index: usize) -> bool {
        index < stream.len()
    }
}

#[derive(Debug, Clone)]
pub struct InsertValue {
    value: InputValue,
}

impl InsertValue {
    fn new(value_type: InputValueType) -> Self {
        Self {
            value: value_type.get_biased_random(),
        }
    }
}

impl Variant for InsertValue {}

impl MutateStream for InsertValue {
    fn mutate(&self, stream: &mut Vec<InputValue>, index: usize) {
        stream.insert(index, self.value.clone());
    }

    fn is_valid(&self, stream: &[InputValue], index: usize) -> bool {
        index <= stream.len()
    }
}

#[derive(Debug, Clone)]
pub struct InsertRepeatedValue {
    count: usize,
    value: InputValue,
}

impl InsertRepeatedValue {
    fn new(value_type: InputValueType) -> Result<Self> {
        let count = random_block_len(3, usize::MAX)?;
        let value = value_type.get_biased_random();

        Ok(Self { count, value })
    }
}

impl Variant for InsertRepeatedValue {}

impl MutateStream for InsertRepeatedValue {
    fn mutate(&self, stream: &mut Vec<InputValue>, index: usize) {
        stream.splice(
            index..index,
            iter::repeat(self.value.clone()).take(self.count),
        );
    }

    fn is_valid(&self, stream: &[InputValue], index: usize) -> bool {
        index <= stream.len()
    }
}

#[derive(Debug, Clone)]
pub struct ChangeValue {
    value: InputValue,
}

impl ChangeValue {
    fn new(value_type: InputValueType) -> Self {
        Self {
            value: value_type.get_biased_random(),
        }
    }
}

impl Variant for ChangeValue {}

impl MutateStream for ChangeValue {
    fn mutate(&self, stream: &mut Vec<InputValue>, index: usize) {
        if let Some(old_value) = stream.get_mut(index) {
            *old_value = self.value.clone();
        }
    }

    fn is_effective(&self, stream: &[InputValue], index: usize) -> bool {
        match stream.get(index) {
            Some(old_value) => self.value != *old_value,
            None => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InvertValueBit {
    bit: u8,
}

impl InvertValueBit {
    fn new(value_type: InputValueType) -> Self {
        Self {
            bit: fastrand::u8(0..value_type.bits()),
        }
    }
}

impl Variant for InvertValueBit {}

impl MutateStream for InvertValueBit {
    fn mutate(&self, stream: &mut Vec<InputValue>, index: usize) {
        if let Some(value) = stream.get_mut(index) {
            value.invert_bit(self.bit);
        }
    }

    fn is_effective(&self, stream: &[InputValue], index: usize) -> bool {
        match stream.get(index) {
            Some(value) => match value.value_type() {
                InputValueType::Choice(_) => {
                    let mut new = value.clone();
                    new.invert_bit(self.bit);

                    new != *value
                }
                _ => true,
            },
            None => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OffsetValue {
    offset: i8,
    overflow: Overflow,
    invert_endianness: bool,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    IndexEnum,
    VariantCount,
    Serialize,
    Deserialize,
)]
pub enum Overflow {
    None,
    Word,
    DWord,
}

impl Overflow {
    fn items(&self) -> usize {
        match self {
            Overflow::None => 1,
            Overflow::Word => 2,
            Overflow::DWord => 4,
        }
    }

    fn random(value_type: InputValueType) -> Self {
        if value_type.is_bit_transparent() {
            Self::index_enum(fastrand::usize(0..Self::VARIANT_COUNT))
                .expect("Overflow index is valid")
        } else {
            Self::None
        }
    }
}

impl OffsetValue {
    fn new(value_type: InputValueType) -> Self {
        let offset = if fastrand::bool() {
            fastrand::i8(1..=10)
        } else {
            fastrand::i8(-10..=-1)
        };
        let overflow = Overflow::random(value_type);
        let invert_endianness = fastrand::bool();

        Self {
            offset,
            overflow,
            invert_endianness,
        }
    }
}

impl Variant for OffsetValue {
    fn variant(&self) -> MutatorVariant {
        MutatorVariant::Offset {
            overflow: self.overflow,
            invert_endianness: self.invert_endianness,
        }
    }
}

fn apply_value_offset(value: &mut InputValue, offset: i8, invert_endianness: bool) {
    if invert_endianness {
        value.invert_endianness();
    }

    value.offset_value(offset);

    if invert_endianness {
        value.invert_endianness();
    }
}

// increment each byte index in items as a target type with overflows
// example:
// items = [ 0x0a01, 0x0b02 ]
// covert to overlfow target:
// overflow = [ 0x0102, 0x0a0b ]
// offset = -5, invert_endianness = false
// overflow = [ 0x00fd, 0x0a06 ]
// covert to source type:
// items = [ 0x0a00, 0x06fd ]
fn apply_overflow_offset(
    target: InputValueType,
    items: &mut [InputValue],
    offset: i8,
    invert_endianness: bool,
) {
    // get source items type
    let source_type = items[0].value_type();

    // collect bytes from N items
    let mut items_bytes: Vec<Vec<u8>> = items
        .iter()
        .take(target.bytes() as usize)
        .map(InputValue::to_bytes)
        .collect();

    // for each byte index in source type do an overflow increment
    for i in 0..(source_type.bytes() as usize) {
        // create overflow input value from bytes over all items at index i
        let overflow_bytes = items_bytes.iter().map(|item_bytes| item_bytes[i]).collect();
        let mut overflow_value =
            InputValue::from_bytes(target, overflow_bytes).expect("type and bytes are valid");

        // apply offset
        apply_value_offset(&mut overflow_value, offset, invert_endianness);

        // split overflow input value into bytes and update bytes in items
        for (item_bytes, overflow_byte) in
            items_bytes.iter_mut().zip(overflow_value.to_bytes().iter())
        {
            item_bytes[i] = *overflow_byte;
        }
    }

    // create new items from updated bytes
    for (item, item_bytes) in items.iter_mut().zip(items_bytes) {
        *item = InputValue::from_bytes(source_type, item_bytes).expect("type and bytes are valid");
    }
}

fn apply_offset(overflow: Overflow, items: &mut [InputValue], offset: i8, invert_endianness: bool) {
    match overflow {
        Overflow::None => apply_value_offset(&mut items[0], offset, invert_endianness),
        Overflow::Word => {
            apply_overflow_offset(InputValueType::Word, items, offset, invert_endianness);
        }
        Overflow::DWord => {
            apply_overflow_offset(InputValueType::DWord, items, offset, invert_endianness);
        }
    }
}

impl MutateStream for OffsetValue {
    fn mutate(&self, stream: &mut Vec<InputValue>, index: usize) {
        apply_offset(
            self.overflow,
            &mut stream[index..],
            self.offset,
            self.invert_endianness,
        )
    }

    fn is_valid(&self, stream: &[InputValue], index: usize) -> bool {
        index + self.overflow.items() <= stream.len()
    }

    fn is_effective(&self, stream: &[InputValue], index: usize) -> bool {
        if self.overflow == Overflow::None {
            match stream.get(index) {
                Some(value) => match value.value_type() {
                    InputValueType::Bits(_) | InputValueType::Choice(_) => {
                        let mut new = value.clone();
                        apply_value_offset(&mut new, self.offset, self.invert_endianness);

                        new != *value
                    }
                    _ => true,
                },
                None => false,
            }
        } else {
            true
        }
    }
}

#[derive(Debug, Clone)]
pub struct ShuffleValues {
    permutation: Vec<(usize, usize)>,
}

impl ShuffleValues {
    fn new() -> Self {
        let count = fastrand::usize(SHUFFLE_RANGE);
        let permutation: Vec<_> = (1..count)
            .rev()
            .map(|i| (i, fastrand::usize(0..i)))
            .collect();

        Self { permutation }
    }
}

impl Variant for ShuffleValues {}

impl MutateStream for ShuffleValues {
    fn mutate(&self, stream: &mut Vec<InputValue>, index: usize) {
        for (a, b) in &self.permutation {
            // skip OOB-swap
            if cmp::max(index + *a, index * b) >= stream.len() {
                continue;
            }

            // invariant: elements with index > i have been locked in place.
            stream.swap(index + *a, index + *b);
        }
    }

    fn is_effective(&self, stream: &[InputValue], index: usize) -> bool {
        // any value differ
        for (a, b) in &self.permutation {
            // skip OOB-swap
            if cmp::max(index + *a, index * b) >= stream.len() {
                continue;
            }

            if stream.get(index + *a) != stream.get(index + *b) {
                return true;
            }
        }

        false
    }
}

#[derive(Debug, Clone)]
pub struct CopyValuePart {
    count: usize,
    source: usize,
    insert: bool,
}

impl Variant for CopyValuePart {
    fn variant(&self) -> MutatorVariant {
        MutatorVariant::Insert(self.insert)
    }
}

impl CopyValuePart {
    fn new(len: usize) -> Result<Self> {
        let count = random_block_len(1, len)?;
        let source = fastrand::usize(0..=(len.saturating_sub(count)));
        let insert = fastrand::bool();

        Ok(Self {
            count,
            source,
            insert,
        })
    }

    fn source(&self, stream: &[InputValue]) -> Range<usize> {
        self.source..cmp::min(self.source + self.count, stream.len())
    }

    fn destination(&self, stream: &[InputValue], index: usize) -> Range<usize> {
        if self.insert {
            index..index
        } else {
            index..cmp::min(index + self.count, stream.len())
        }
    }
}

impl MutateStream for CopyValuePart {
    fn mutate(&self, stream: &mut Vec<InputValue>, index: usize) {
        let source = self.source(stream);
        let destination = self.destination(stream, index);
        let data = stream[source].to_vec();
        stream.splice(destination, data);
    }

    fn is_valid(&self, stream: &[InputValue], index: usize) -> bool {
        index <= stream.len() && self.source < stream.len()
    }

    fn is_effective(&self, stream: &[InputValue], index: usize) -> bool {
        if self.insert {
            true
        } else {
            let destination = self.destination(stream, index);
            let destination_end = destination.end;

            for (src, dst) in self
                .source(stream)
                .zip(destination.chain(iter::repeat(destination_end)))
            {
                if stream.get(src) != stream.get(dst) {
                    return true;
                }
            }

            false
        }
    }
}

#[derive(Debug, Clone)]
pub struct CrossOverValuePart {
    insert: bool,
    data: Vec<InputValue>,
}

impl CrossOverValuePart {
    fn new(cross_over: &InputStream) -> Result<Self> {
        let len = cross_over.len();
        let count = random_block_len(1, len)?;
        let source = fastrand::usize(0..=(len.saturating_sub(count)));
        let data = cross_over.as_ref()[source..(source + count)].to_vec();

        Ok(Self {
            insert: fastrand::bool(),
            data,
        })
    }

    fn destination(&self, stream: &[InputValue], index: usize) -> Range<usize> {
        if self.insert {
            index..index
        } else {
            index..cmp::min(index + self.data.len(), stream.len())
        }
    }
}

impl Variant for CrossOverValuePart {
    fn variant(&self) -> MutatorVariant {
        MutatorVariant::Insert(self.insert)
    }
}

impl MutateStream for CrossOverValuePart {
    fn mutate(&self, stream: &mut Vec<InputValue>, index: usize) {
        stream.splice(self.destination(stream, index), self.data.iter().cloned());
    }

    fn is_valid(&self, stream: &[InputValue], index: usize) -> bool {
        index <= stream.len()
    }

    fn is_effective(&self, stream: &[InputValue], index: usize) -> bool {
        if self.insert {
            !self.data.is_empty()
        } else {
            let destination = self.destination(stream, index);
            let destination_end = destination.end;

            for (idx, dst) in
                (0..self.data.len()).zip(destination.chain(iter::repeat(destination_end)))
            {
                if self.data.get(idx) != stream.get(dst) {
                    return true;
                }
            }

            false
        }
    }
}

#[derive(Debug, Clone)]
pub struct Splice {
    insert: bool,
    data: FxHashMap<InputContext, Vec<InputValue>>,
}

impl Splice {
    pub fn new(cross_over: &InputResult, context: &InputContext) -> Result<Self> {
        // chrono stream
        let file = cross_over.file();
        let chrono_stream = cross_over.chrono_stream();

        // get random index in target stream
        let target = StreamIndex {
            context: context.clone(),
            index: file
                .input_streams()
                .get(context)
                .map(|stream| {
                    if !stream.is_empty() {
                        fastrand::usize(0..stream.len())
                    } else {
                        0
                    }
                })
                .unwrap_or_default(),
        };

        // chrono stream range
        let start = chrono_stream
            .chrono_index(&target)
            .context("Invalid StreamIndex")?;
        let count = random_block_len(1, chrono_stream.len() - start)?;
        let chrono_range = start..(start + count);

        // copy source stream ranges
        let mut data = FxHashMap::default();
        for (context, stream) in file.input_streams() {
            if let Some(range) = chrono_stream
                .stream_range(context, &chrono_range)
                .filter(|range| !range.is_empty())
            {
                data.insert(context.clone(), stream.as_ref()[range].to_vec());
            }
        }

        Ok(Self {
            insert: fastrand::bool(),
            data,
        })
    }

    fn destination(
        &self,
        chrono_stream: &ChronoStream,
        target: &StreamIndex,
    ) -> Result<Range<usize>> {
        let start = chrono_stream
            .chrono_index(target)
            .context("Invalid StreamIndex")?;

        let end = if self.insert {
            start
        } else {
            start + self.data.values().map(|values| values.len()).sum::<usize>()
        };

        Ok(start..end)
    }
}

impl Variant for Splice {
    fn variant(&self) -> MutatorVariant {
        MutatorVariant::Insert(self.insert)
    }
}

impl Mutate for Splice {
    fn mutate(&self, input: &mut InputFork, target: &StreamIndex) -> Result<()> {
        let (file, chrono_stream) = input.inner_ref_mut();

        // chrono stream ranges
        let dst = self.destination(chrono_stream, target)?;

        // copy stream ranges
        for (context, values) in &self.data {
            // get stream or create empty
            let (stream, dst_range) = match file.input_streams_mut().entry(context.clone()) {
                Entry::Occupied(entry) => {
                    let stream = entry.into_mut();
                    let dst_range = match chrono_stream.stream_range(context, &dst) {
                        Some(dst_range) => {
                            dst_range.start.min(stream.len())..dst_range.end.min(stream.len())
                        }
                        None => continue,
                    };

                    (stream, dst_range)
                }
                Entry::Vacant(entry) => {
                    (entry.insert(InputStream::new(values[0].value_type())), 0..0)
                }
            };

            stream.as_mut().splice(dst_range, values.iter().cloned());
        }

        Ok(())
    }

    fn is_valid_and_effective(&self, input: &InputFork, target: &StreamIndex) -> bool {
        if self.insert {
            input.chrono_stream().chrono_index(target).is_some() && !self.data.is_empty()
        } else {
            let (file, chrono_stream) = input.inner_ref();

            // chrono stream ranges
            if let Ok(dst) = self.destination(chrono_stream, target) {
                // compare stream range
                for (context, values) in &self.data {
                    match (
                        chrono_stream.stream_range(context, &dst),
                        file.input_streams().get(context),
                    ) {
                        (Some(dst_range), Some(stream)) => {
                            if values[..]
                                != stream.as_ref()[dst_range.start.min(stream.len())
                                    ..dst_range.end.min(stream.len())]
                            {
                                return true;
                            }
                        }
                        _ => {
                            return false;
                        }
                    }
                }
            }

            false
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChronoEraseValues {
    count: usize,
}

impl ChronoEraseValues {
    pub fn new(file_len: usize) -> Result<Self> {
        let count = random_block_len(1, file_len)?;
        Ok(Self { count })
    }
}

impl Variant for ChronoEraseValues {}

impl Mutate for ChronoEraseValues {
    fn mutate(&self, input: &mut InputFork, target: &StreamIndex) -> Result<()> {
        let (file, chrono_stream) = input.inner_ref_mut();

        // chrono stream range
        let start = chrono_stream
            .chrono_index(target)
            .context("Invalid StreamIndex")?;
        let end = start + self.count;
        let chrono_range = start..end;

        // erase stream ranges
        for (context, stream) in file.input_streams_mut() {
            if stream.is_empty() {
                continue;
            }

            if let Some(range) = chrono_stream.stream_range(context, &chrono_range) {
                let range = range.start.min(stream.len())..range.end.min(stream.len());

                stream.as_mut().splice(range, iter::empty());
            }
        }

        Ok(())
    }

    fn is_valid_and_effective(&self, input: &InputFork, target: &StreamIndex) -> bool {
        input.chrono_stream().chrono_index(target).is_some()
    }
}

#[derive(Debug, Clone)]
pub struct ChronoCopyValuePart {
    index: usize,
    count: usize,
    insert: bool,
}

impl ChronoCopyValuePart {
    pub fn new(file_len: usize) -> Result<Self> {
        let count = random_block_len(1, file_len)?;
        let index = fastrand::usize(0..=(file_len.saturating_sub(count)));
        let insert = fastrand::bool();

        Ok(Self {
            index,
            count,
            insert,
        })
    }

    fn source(&self) -> Range<usize> {
        self.index..(self.index + self.count)
    }

    fn destination(
        &self,
        chrono_stream: &ChronoStream,
        target: &StreamIndex,
    ) -> Result<Range<usize>> {
        let start = chrono_stream
            .chrono_index(target)
            .context("Invalid StreamIndex")?;

        let end = if self.insert {
            start
        } else {
            start + self.count
        };

        Ok(start..end)
    }
}

impl Variant for ChronoCopyValuePart {
    fn variant(&self) -> MutatorVariant {
        MutatorVariant::Insert(self.insert)
    }
}

impl Mutate for ChronoCopyValuePart {
    fn mutate(&self, input: &mut InputFork, target: &StreamIndex) -> Result<()> {
        let (file, chrono_stream) = input.inner_ref_mut();

        // chrono stream ranges
        let src = self.source();
        let dst = self.destination(chrono_stream, target)?;

        // copy stream ranges
        for (context, stream) in file.input_streams_mut() {
            if stream.is_empty() {
                continue;
            }

            if let (Some(src_range), Some(dst_range)) = (
                chrono_stream.stream_range(context, &src),
                chrono_stream.stream_range(context, &dst),
            ) {
                let src_range = src_range.start.min(stream.len())..src_range.end.min(stream.len());
                let dst_range = dst_range.start.min(stream.len())..dst_range.end.min(stream.len());

                let data: Vec<_> = stream.as_ref()[src_range].to_vec();
                stream.as_mut().splice(dst_range, data);
            }
        }

        Ok(())
    }

    fn is_valid_and_effective(&self, input: &InputFork, target: &StreamIndex) -> bool {
        if self.insert {
            self.destination(input.chrono_stream(), target).is_ok()
        } else {
            let (file, chrono_stream) = input.inner_ref();

            if let Ok(dst) = self.destination(chrono_stream, target) {
                // chrono stream range
                let src = self.source();

                // compare stream ranges
                for (context, stream) in file.input_streams() {
                    if stream.is_empty() {
                        continue;
                    }

                    match (
                        chrono_stream.stream_range(context, &src),
                        chrono_stream.stream_range(context, &dst),
                    ) {
                        (Some(src_range), Some(dst_range)) => {
                            let src_range =
                                src_range.start.min(stream.len())..src_range.end.min(stream.len());
                            let dst_range =
                                dst_range.start.min(stream.len())..dst_range.end.min(stream.len());

                            if stream.as_ref()[src_range] != stream.as_ref()[dst_range] {
                                return true;
                            }
                        }
                        _ => {
                            return false;
                        }
                    }
                }
            }

            false
        }
    }
}

#[derive(Debug, Clone)]
pub struct Dictionary(CrossOverValuePart);

impl Dictionary {
    fn new(value_type: InputValueType, dict: &dict::Dictionary) -> Option<Self> {
        if value_type.is_bit_transparent() {
            Some(Self(CrossOverValuePart {
                insert: fastrand::bool(),
                data: dict
                    .random_entry()?
                    .as_ref()
                    .iter()
                    .copied()
                    .map(|byte| InputValue::from_repeated_byte(value_type, byte))
                    .collect(),
            }))
        } else {
            None
        }
    }
}

impl Variant for Dictionary {
    fn variant(&self) -> MutatorVariant {
        self.0.variant()
    }
}

impl MutateStream for Dictionary {
    fn mutate(&self, stream: &mut Vec<InputValue>, index: usize) {
        MutateStream::mutate(&self.0, stream, index)
    }

    fn is_valid(&self, stream: &[InputValue], index: usize) -> bool {
        self.0.is_valid(stream, index)
    }

    fn is_effective(&self, stream: &[InputValue], index: usize) -> bool {
        self.0.is_effective(stream, index)
    }
}

#[derive(Debug, Clone)]
pub struct InterestingValue(CrossOverValuePart);

impl InterestingValue {
    fn new(value_type: InputValueType) -> Result<Self> {
        let data = match value_type {
            InputValueType::Byte
            | InputValueType::Word
            | InputValueType::DWord
            | InputValueType::Bits(_) => interesting_value_overflow(value_type),
            InputValueType::Choice(len) => {
                if fastrand::bool() {
                    choice_pattern_abab(len)?
                } else {
                    choice_pattern_abcd(len)?
                }
            }
        };

        Ok(Self(CrossOverValuePart {
            insert: fastrand::bool(),
            data,
        }))
    }
}

fn interesting_value_overflow(value_type: InputValueType) -> Vec<InputValue> {
    let value = if fastrand::bool() {
        InputValueType::Word
    } else {
        InputValueType::DWord
    }
    .get_random_interesting_value()
    .unwrap();

    value
        .to_bytes()
        .into_iter()
        .map(|byte| InputValue::from_repeated_byte(value_type, byte))
        .collect()
}

fn choice_pattern_abab(len: u8) -> Result<Vec<InputValue>> {
    // pick two distinct random choice indices
    let a = fastrand::u8(0..len);
    let tmp = fastrand::u8(0..(len - 1));
    let b = if tmp >= a { tmp + 1 } else { tmp };

    Ok(itertools::interleave(iter::repeat(a), iter::repeat(b))
        .map(|index| InputValue::Choice { len, index })
        .take(random_block_len(4, usize::MAX)?)
        .collect())
}

fn choice_pattern_abcd(len: u8) -> Result<Vec<InputValue>> {
    Ok((0..len)
        .map(|index| InputValue::Choice { len, index })
        .cycle()
        .take(random_block_len(len as usize, usize::MAX)?)
        .collect())
}

impl Variant for InterestingValue {
    fn variant(&self) -> MutatorVariant {
        self.0.variant()
    }
}

impl MutateStream for InterestingValue {
    fn mutate(&self, stream: &mut Vec<InputValue>, index: usize) {
        MutateStream::mutate(&self.0, stream, index)
    }

    fn is_valid(&self, stream: &[InputValue], index: usize) -> bool {
        self.0.is_valid(stream, index)
    }

    fn is_effective(&self, stream: &[InputValue], index: usize) -> bool {
        self.0.is_effective(stream, index)
    }
}
