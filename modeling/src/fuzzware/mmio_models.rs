use indexmap::IndexMap;
use qemu_rs::{Address, USize};
use serde::{Deserialize, Serialize};

use crate::{
    mmio::{AccessContext, Mmio, MmioContext, ModelContext},
    mmio_model::{MmioModel, ModelBitExtract},
};

trait ModelConvert {
    fn convert(&self) -> Mmio;
}

#[derive(Debug)]
struct FuzzwareContext {
    pc: Address,
    addr: Address,
}

impl FuzzwareContext {
    fn new(pc: Address, addr: Address) -> Self {
        Self { pc, addr }
    }
}

impl Into<ModelContext> for FuzzwareContext {
    fn into(self) -> ModelContext {
        const MMIO_HOOK_PC_ALL_ACCESS_SITES: Address = 0xffffffff;

        if self.pc != MMIO_HOOK_PC_ALL_ACCESS_SITES {
            ModelContext::AccessContext(AccessContext::new(self.pc, self.addr))
        } else {
            ModelContext::MmioContext(MmioContext::new(self.addr))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct FuzzwareMmio {
    mmio_models: MmioModels,
}

impl FuzzwareMmio {
    pub fn convert(&self) -> impl Iterator<Item = Mmio> + '_ {
        self.mmio_models.convert()
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct MmioModels {
    bitextract: Option<IndexMap<String, Bitextract>>,
    constant: Option<IndexMap<String, Constant>>,
    passthrough: Option<IndexMap<String, Passthrough>>,
    set: Option<IndexMap<String, Set>>,
    // TODO: unmodeled
}

impl MmioModels {
    pub fn convert(&self) -> impl Iterator<Item = Mmio> + '_ {
        to_iter(&self.bitextract)
            .chain(to_iter(&self.constant))
            .chain(to_iter(&self.passthrough))
            .chain(to_iter(&self.set))
    }
}

fn to_iter<K, T: ModelConvert>(models: &Option<IndexMap<K, T>>) -> impl Iterator<Item = Mmio> + '_ {
    models
        .iter()
        .flat_map(|models| models.values().map(ModelConvert::convert))
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
struct Bitextract {
    pc: Address,
    addr: Address,
    left_shift: u8,
    mask: Address,
    size: u8,
}

impl ModelConvert for Bitextract {
    fn convert(&self) -> Mmio {
        let bits = self.size * (u8::BITS as u8);
        let left_shift = self.left_shift - (self.left_shift % u8::BITS as u8);
        let be = ModelBitExtract::new(bits, left_shift);

        Mmio {
            context: FuzzwareContext::new(self.pc, self.addr).into(),
            model: Some(MmioModel::BitExtract(be)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
struct Constant {
    pc: Address,
    addr: Address,
    val: USize,
}

impl ModelConvert for Constant {
    fn convert(&self) -> Mmio {
        Mmio {
            context: FuzzwareContext::new(self.pc, self.addr).into(),
            model: Some(MmioModel::Constant { value: self.val }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
struct Passthrough {
    pc: Address,
    addr: Address,
    init_val: Option<USize>,
}

impl ModelConvert for Passthrough {
    fn convert(&self) -> Mmio {
        Mmio {
            context: FuzzwareContext::new(self.pc, self.addr).into(),
            model: Some(MmioModel::Passthrough {
                initial_value: self.init_val.unwrap_or(0),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
struct Set {
    pc: Address,
    addr: Address,
    vals: Vec<USize>,
}
impl ModelConvert for Set {
    fn convert(&self) -> Mmio {
        Mmio {
            context: FuzzwareContext::new(self.pc, self.addr).into(),
            model: Some(MmioModel::Set {
                values: self.vals.clone(),
            }),
        }
    }
}
