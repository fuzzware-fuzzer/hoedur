use qemu_rs::{Address, MmioAddress, USize};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Debug},
    mem,
};

use crate::mmio_model::MmioModel;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ModelContext {
    AccessContext(AccessContext),
    MmioContext(MmioContext),
}

impl fmt::Display for ModelContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ModelContext::AccessContext(context) => write!(f, "{context}"),
            ModelContext::MmioContext(context) => write!(f, "{context}"),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessContext {
    pc: Address,
    #[serde(flatten)]
    mmio: MmioContext,
}

impl AccessContext {
    pub fn new(pc: Address, mmio: MmioAddress) -> Self {
        Self {
            pc,
            mmio: MmioContext::new(mmio),
        }
    }

    pub fn pc(&self) -> Address {
        self.pc
    }

    pub fn mmio(&self) -> &MmioContext {
        &self.mmio
    }
}

impl fmt::Display for AccessContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}_{}", self.pc, self.mmio)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmioContext {
    #[serde(rename = "mmio")]
    addr: MmioAddress,
}

impl MmioContext {
    pub fn new(addr: MmioAddress) -> Self {
        Self { addr }
    }

    pub fn addr(&self) -> MmioAddress {
        self.addr
    }

    pub fn addr_aligned(&self) -> MmioAddress {
        aligned(self.addr)
    }
}

impl fmt::Display for MmioContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.addr as u8)
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Mmio {
    pub context: ModelContext,
    pub model: Option<MmioModel>,
}

pub fn aligned(address: MmioAddress) -> MmioAddress {
    address & !(mem::size_of::<USize>() as MmioAddress - 1)
}
