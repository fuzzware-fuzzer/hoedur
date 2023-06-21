use common::config::fuzzer::{SizeDistributionScale, SIZE_DISTRIBUTION_SCALE};
use serde::{Deserialize, Serialize};
use std::{fmt, hash::Hash, rc::Rc};

use crate::input::value::{InputValue, InputValueType};

const ARROW: &str = " => ";
const SPACE: &str = "    ";

pub trait Stream {
    type Value: Default + Clone;

    fn cursor(&self) -> usize;

    fn len(&self) -> usize {
        self.as_ref().len()
    }
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn as_ref(&self) -> &[Self::Value];
    fn as_mut(&mut self) -> &mut Vec<Self::Value>;
}

pub(crate) trait StreamInternal: Stream + Sized {
    /// throw out input after cursor
    fn minimize(&mut self) {
        let cursor = self.cursor();
        self.as_mut().resize(cursor, Self::Value::default());
    }

    fn set_cursor(&mut self, cursor: usize);

    fn merge(&mut self, mut other: Self) {
        self.as_mut().append(other.as_mut());
    }

    fn split(&self) -> Self;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputStream {
    value_type: InputValueType,
    stream: Rc<Vec<InputValue>>,
    #[serde(skip)]
    cursor: usize,
}

impl Hash for InputStream {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.value_type.hash(state);
        self.stream.hash(state);
    }
}

impl PartialEq for InputStream {
    fn eq(&self, other: &Self) -> bool {
        self.value_type == other.value_type && self.stream == other.stream
    }
}

impl fmt::Display for InputStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (idx, value) in self.stream.iter().enumerate() {
            let pointer = if idx == self.cursor() { ARROW } else { SPACE };
            write!(f, "{pointer}{value}")?;

            if value.value_type().is_bit_transparent() {
                write!(f, "\t|")?;
                for byte in value.to_bytes() {
                    if (0x20..0x7f).contains(&byte) {
                        write!(f, "{}", char::from(byte))?;
                    } else {
                        write!(f, ".")?;
                    }
                }
                write!(f, "|")?;
            }

            writeln!(f)?;
        }

        if self.cursor() == self.stream.len() {
            writeln!(f, "{ARROW}")?;
        }

        Ok(())
    }
}

impl InputStream {
    pub fn new(value_type: InputValueType) -> Self {
        Self {
            value_type,
            stream: Rc::new(vec![]),
            cursor: 0,
        }
    }

    pub fn fork(&self) -> Self {
        Self {
            value_type: self.value_type,
            stream: self.stream.clone(),
            cursor: 0,
        }
    }

    pub fn next_or_random<F>(&mut self, random_available: F) -> Option<&InputValue>
    where
        F: FnOnce(&Self) -> bool,
    {
        debug_assert!(self.cursor <= self.stream.len());

        if self.cursor < self.stream.len() {
            let value = &self.stream[self.cursor];
            self.validate_value_type(value);
            self.cursor += 1;
            Some(value)
        } else if random_available(self) {
            Some(self.next_random())
        } else {
            None
        }
    }

    pub fn next(&mut self) -> Option<&InputValue> {
        debug_assert!(self.cursor <= self.stream.len());

        let value = self.stream.get(self.cursor);

        if let Some(value) = value {
            self.validate_value_type(value);
            self.cursor += 1;
        }

        value
    }

    pub fn next_random(&mut self) -> &InputValue {
        debug_assert!(self.cursor == self.stream.len());

        Rc::make_mut(&mut self.stream).push(self.value_type.get_biased_random());
        let value = &self.stream[self.cursor];
        self.validate_value_type(value);
        self.cursor += 1;

        value
    }

    pub fn push_value(&mut self, value: InputValue) {
        self.validate_value_type(&value);
        Rc::make_mut(&mut self.stream).push(value);
    }

    fn validate_value_type(&self, value: &InputValue) {
        debug_assert_eq!(
            value.value_type(),
            self.value_type(),
            "Invalid value type: {:?} expected {:?}",
            value.value_type(),
            self.value_type()
        );
    }

    pub fn value_type(&self) -> InputValueType {
        self.value_type
    }

    pub fn scaled_size(&self) -> usize {
        self.scaled_size_by(SIZE_DISTRIBUTION_SCALE)
    }

    pub fn scaled_size_by(&self, scale: SizeDistributionScale) -> usize {
        let bits_clamp = || self.value_type.bits().clamp(1, 8);

        let scale = match scale {
            SizeDistributionScale::Bits => self.value_type.bits() as usize,
            SizeDistributionScale::BitValues => bits_clamp() as usize,
            SizeDistributionScale::BitValuesPow2 => 2usize.pow(bits_clamp() as u32),
            SizeDistributionScale::Bytes => self.value_type.bytes() as usize,
            SizeDistributionScale::Values => 1,
        };

        self.len() * scale
    }

    pub fn bytes(&self) -> usize {
        self.len() * (self.value_type.bytes() as usize)
    }
}

impl Stream for InputStream {
    type Value = InputValue;

    fn cursor(&self) -> usize {
        self.cursor
    }

    fn as_ref(&self) -> &[Self::Value] {
        &self.stream
    }

    fn as_mut(&mut self) -> &mut Vec<Self::Value> {
        Rc::make_mut(&mut self.stream)
    }
}

impl StreamInternal for InputStream {
    fn set_cursor(&mut self, cursor: usize) {
        debug_assert!(cursor <= self.len());
        self.cursor = cursor;
    }

    fn split(&self) -> Self {
        Self {
            value_type: self.value_type(),
            stream: Rc::new(self.as_ref()[self.cursor()..].to_vec()),
            cursor: 0,
        }
    }
}
