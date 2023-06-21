use common::config::mutation::{
    INTERESTING_VALUES_U16, INTERESTING_VALUES_U32, INTERESTING_VALUES_U8,
};
use serde::{Deserialize, Serialize};
use std::{
    convert::TryInto,
    fmt::{self, Debug},
};

use crate::mmio_model::{bit_mask, ReadSize};

#[derive(Debug, Hash, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum InputValue {
    Byte(u8),
    Word(u16),
    DWord(u32),
    Bits { bits: u8, value: u32 },
    Choice { len: u8, index: u8 },
}

impl fmt::Display for InputValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Byte(value) => write!(f, "{value:#04x?}"),
            Self::Word(value) => write!(f, "{value:#06x?}"),
            Self::DWord(value) => write!(f, "{value:#010x?}"),
            Self::Bits { value, bits } if (bits % u8::BITS as u8) == 0 => {
                write!(f, "{:#0width$x?}", value, width = 2 + (*bits as usize / 4))
            }
            Self::Bits { value, bits } => {
                write!(f, "{:#0width$b}", value, width = 2 + *bits as usize)
            }
            Self::Choice { index, .. } => write!(f, "{index}"),
        }
    }
}

impl InputValue {
    pub fn from_bytes(value_type: InputValueType, bytes: Vec<u8>) -> Result<Self, Vec<u8>> {
        Ok(match value_type {
            InputValueType::Byte => Self::Byte(u8::from_be_bytes(bytes.try_into()?)),
            InputValueType::Word => Self::Word(u16::from_be_bytes(bytes.try_into()?)),
            InputValueType::DWord => Self::DWord(u32::from_be_bytes(bytes.try_into()?)),
            InputValueType::Bits(bits) => Self::Bits {
                bits,
                value: match value_type.bytes() {
                    1 => u8::from_be_bytes(bytes.try_into()?) as u32,
                    2 => u16::from_be_bytes(bytes.try_into()?) as u32,
                    3 => u32::from_be_bytes([&[0x00], &bytes[..]].concat().try_into()?),
                    4 => u32::from_be_bytes(bytes.try_into()?),
                    _ => unreachable!(),
                } & bit_mask(bits),
            },
            InputValueType::Choice(len) => Self::Choice {
                len,
                index: u8::from_be_bytes(bytes.try_into()?) % len,
            },
        })
    }

    pub fn from_repeated_byte(value_type: InputValueType, byte: u8) -> Self {
        let to_u16 = |byte| (byte as u16) << u8::BITS | byte as u16;
        let to_u32 = |byte| (to_u16(byte) as u32) << u16::BITS | to_u16(byte) as u32;

        match value_type {
            InputValueType::Byte => Self::Byte(byte),
            InputValueType::Word => Self::Word(to_u16(byte)),
            InputValueType::DWord => Self::DWord(to_u32(byte)),
            InputValueType::Bits(bits) => Self::Bits {
                bits,
                value: to_u32(byte) & bit_mask(bits),
            },
            InputValueType::Choice(len) => Self::Choice {
                len,
                index: byte % len,
            },
        }
    }

    pub fn value_type(&self) -> InputValueType {
        match self {
            Self::Byte(_) => InputValueType::Byte,
            Self::Word(_) => InputValueType::Word,
            Self::DWord(_) => InputValueType::DWord,
            Self::Bits { bits, .. } => InputValueType::Bits(*bits),
            Self::Choice { len, .. } => InputValueType::Choice(*len),
        }
    }

    pub fn invert_bit(&mut self, bit: u8) {
        debug_assert!(bit < self.value_type().bits());

        match self {
            Self::Byte(value) => *value ^= 1 << bit,
            Self::Word(value) => *value ^= 1 << bit,
            Self::DWord(value) => *value ^= 1 << bit,
            Self::Bits { value, .. } => *value ^= 1 << bit,
            Self::Choice { index, len } => *index = (*index ^ (1 << bit)) % *len,
        }
    }

    pub fn invert_endianness(&mut self) {
        match self {
            Self::Word(value) => *value = u16::from_le(u16::from_be(*value)),
            Self::DWord(value) => *value = u32::from_le(u32::from_be(*value)),
            Self::Byte(_) | Self::Bits { .. } | Self::Choice { .. } => {}
        }
    }

    pub fn offset_value(&mut self, offset: i8) {
        match self {
            Self::Byte(value) => *value = value.wrapping_add(offset as u8),
            Self::Word(value) => *value = value.wrapping_add(offset as u16),
            Self::DWord(value) => *value = value.wrapping_add(offset as u32),
            Self::Bits { bits, value } => {
                *value = value.wrapping_add(offset as u32) & bit_mask(*bits)
            }
            Self::Choice { len, index } => *index = index.wrapping_add(offset as u8) % *len,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Byte(value) => value.to_be_bytes().to_vec(),
            Self::Word(value) => value.to_be_bytes().to_vec(),
            Self::DWord(value) => value.to_be_bytes().to_vec(),
            Self::Bits { bits, value } => {
                let mut bytes = value.to_be_bytes().to_vec();

                // remove unused bytes
                for _ in 0..((u32::BITS - *bits as u32) / 8) {
                    bytes.remove(0);
                }

                bytes
            }
            Self::Choice { index, .. } => index.to_be_bytes().to_vec(),
        }
    }
}

impl Default for InputValue {
    fn default() -> Self {
        InputValue::Byte(0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum InputValueType {
    Byte,
    Word,
    DWord,
    Bits(u8),
    Choice(u8),
}

impl fmt::Display for InputValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Byte => "byte",
                Self::Word => "word",
                Self::DWord => "dword",
                Self::Bits(_) => "bits",
                Self::Choice(_) => "choice",
            }
        )?;

        match self {
            Self::Byte | Self::Word | Self::DWord => Ok(()),
            Self::Bits(value) | Self::Choice(value) => write!(f, "-{value}"),
        }
    }
}

impl Default for InputValueType {
    fn default() -> Self {
        Self::DWord
    }
}

impl InputValueType {
    pub fn get_zero(&self) -> Option<InputValue> {
        Some(match self {
            Self::Byte => InputValue::Byte(u8::MIN),
            Self::Word => InputValue::Word(u16::MIN),
            Self::DWord => InputValue::DWord(u32::MIN),
            Self::Bits(bits) => InputValue::Bits {
                bits: *bits,
                value: u32::MIN,
            },
            Self::Choice(_) => return None,
        })
    }

    pub fn get_max_value(&self) -> Option<InputValue> {
        Some(match self {
            Self::Byte => InputValue::Byte(u8::MAX),
            Self::Word => InputValue::Word(u16::MAX),
            Self::DWord => InputValue::DWord(u32::MAX),
            Self::Bits(bits) => InputValue::Bits {
                bits: *bits,
                value: u32::MAX & bit_mask(*bits),
            },
            Self::Choice(_) => return None,
        })
    }

    fn get_true_random(&self) -> InputValue {
        match self {
            Self::Byte => InputValue::Byte(fastrand::u8(..)),
            Self::Word => InputValue::Word(fastrand::u16(..)),
            Self::DWord => InputValue::DWord(fastrand::u32(..)),
            Self::Bits(bits) => InputValue::Bits {
                bits: *bits,
                value: fastrand::u32(..) & bit_mask(*bits),
            },
            Self::Choice(len) => InputValue::Choice {
                len: *len,
                index: fastrand::u8(0..*len),
            },
        }
    }

    pub fn get_random_interesting_value(&self) -> Option<InputValue> {
        Some(match self {
            Self::Byte => InputValue::Byte(interesting_values_u8()),
            Self::Word => InputValue::Word(interesting_values_u16()),
            Self::DWord => InputValue::DWord(interesting_values_u32()),
            Self::Bits(bits) => InputValue::Bits {
                bits: *bits,
                value: match bits {
                    8 => interesting_values_u8() as u32,
                    16 => interesting_values_u16() as u32,
                    32 => interesting_values_u32(),
                    _ => return None,
                },
            },
            Self::Choice(_) => return None,
        })
    }

    pub fn get_biased_random(&self) -> InputValue {
        match fastrand::u8(0..100) {
            // 25% zero
            0..=24 => self.get_zero(),
            // 25% interesting values
            25..=49 => self.get_random_interesting_value(),
            // 50% true random
            _ => Some(self.get_true_random()),
        }
        // fallback to true random, e.g. when no interesting values are available for choice
        .unwrap_or_else(|| self.get_true_random())
    }

    pub fn bits(&self) -> u8 {
        match self {
            Self::Byte => u8::BITS as u8,
            Self::Word => u16::BITS as u8,
            Self::DWord => u32::BITS as u8,
            Self::Bits(bits) => *bits,
            Self::Choice(len) => (u8::BITS - (len - 1).leading_zeros()) as u8,
        }
    }

    pub fn bytes(&self) -> u8 {
        // TODO: use next_multiple_of when #88581 lands
        (self.bits() + u8::BITS as u8 - 1) / u8::BITS as u8
    }

    pub fn is_bit_transparent(&self) -> bool {
        match self {
            InputValueType::Choice(_) => false,
            InputValueType::Byte
            | InputValueType::Word
            | InputValueType::DWord
            | InputValueType::Bits(_) => true,
        }
    }
}

impl From<ReadSize> for InputValueType {
    fn from(size: ReadSize) -> Self {
        match size {
            ReadSize::Byte => InputValueType::Byte,
            ReadSize::Word => InputValueType::Word,
            ReadSize::DWord => InputValueType::DWord,
            ReadSize::QWord => unimplemented!("ReadSize::QWord is currently not implemented"),
        }
    }
}

fn interesting_values_u8() -> u8 {
    INTERESTING_VALUES_U8[fastrand::usize(0..INTERESTING_VALUES_U8.len())]
}
fn interesting_values_u16() -> u16 {
    let value = INTERESTING_VALUES_U16[fastrand::usize(0..INTERESTING_VALUES_U16.len())];

    if fastrand::bool() {
        value
    } else {
        u16::from_le(u16::from_be(value))
    }
}
fn interesting_values_u32() -> u32 {
    let value = INTERESTING_VALUES_U32[fastrand::usize(0..INTERESTING_VALUES_U32.len())];

    if fastrand::bool() {
        value
    } else {
        u32::from_le(u32::from_be(value))
    }
}
