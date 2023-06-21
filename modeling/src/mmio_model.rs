use anyhow::bail;
use qemu_rs::USize;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Debug, Clone, Hash, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MmioModel {
    BitExtract(ModelBitExtract),
    Constant { value: USize },
    Passthrough { initial_value: USize },
    Set { values: Vec<USize> },
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ReadSize {
    Byte = 1,
    Word = 2,
    DWord = 4,
    QWord = 8,
}

impl ReadSize {
    pub fn try_from_bits(bits: u32) -> anyhow::Result<Self> {
        Ok(match bits {
            0 => bail!("invalid ReadSize with zero bits"),
            1..=8 => ReadSize::Byte,
            9..=16 => ReadSize::Word,
            17..=32 => ReadSize::DWord,
            33..=64 => ReadSize::DWord,
            65.. => bail!("invalid ReadSize with more bits than u64::BITS"),
        })
    }

    pub fn bits(self) -> u32 {
        match self {
            ReadSize::Byte => u8::BITS,
            ReadSize::Word => u16::BITS,
            ReadSize::DWord => u32::BITS,
            ReadSize::QWord => u64::BITS,
        }
    }

    pub fn mask(self) -> USize {
        bit_mask(self.bits() as u8)
    }
}

impl TryFrom<u32> for ReadSize {
    type Error = anyhow::Error;

    fn try_from(size: u32) -> Result<Self, Self::Error> {
        Ok(match size {
            1 => Self::Byte,
            2 => Self::Word,
            4 => Self::DWord,
            8 => Self::QWord,
            _ => bail!("Unknown Read Size: {:#x?}", size),
        })
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Deserialize, Serialize)]
pub struct ModelBitExtract {
    pub(crate) bits: u8,
    pub(crate) left_shift: u8,
}

impl ModelBitExtract {
    pub fn new(bits: u8, left_shift: u8) -> Self {
        Self { bits, left_shift }
    }

    pub fn bits(&self) -> u8 {
        self.bits
    }

    pub fn left_shift(&self) -> u8 {
        self.left_shift
    }

    fn mask(&self) -> USize {
        bit_mask(self.bits)
    }

    pub fn apply(&self, value: USize) -> USize {
        (value & self.mask()) << self.left_shift
    }

    pub fn size(&self) -> ReadSize {
        ReadSize::try_from_bits(self.bits as u32).expect("Valid ModelBitExtract")
    }
}

pub fn bit_mask(bits: u8) -> u32 {
    USize::MAX >> (USize::BITS - bits as u32)
}
