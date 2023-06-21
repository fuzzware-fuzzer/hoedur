use anyhow::{bail, Context, Result};
use frametracer::symbolizer::Symbolizer;
use qemu_rs::Address;
use serde::{Deserialize, Serialize};

pub(crate) mod custom;
pub(crate) mod debug;
pub(crate) mod exit;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HookTarget {
    BasicBlock {
        pc: Address,
    },
    Function {
        symbol: String,
        offset: Option<Address>,
    },
}

impl HookTarget {
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Function { symbol, .. } => Some(symbol.as_str()),
            Self::BasicBlock { .. } => None,
        }
    }

    pub fn resolve(&self, symbolizer: &Symbolizer) -> Result<Vec<Address>> {
        match self {
            Self::BasicBlock { pc } => Ok(vec![*pc]),
            Self::Function { symbol, offset } => {
                let offset = offset.unwrap_or(0);
                let addresses = symbolizer
                    .resolve_symbol_with_offset(symbol.as_str(), offset)
                    .map(|result| {
                        result.with_context(|| {
                            format!(
                                "Failed resolve symbol {symbol:?} with offset {:08x}",
                                offset
                            )
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;

                if addresses.is_empty() {
                    bail!(
                        "Could not resolve {:?}: no valid symbol addresses found.",
                        self
                    );
                } else if addresses.len() > 1 {
                    log::debug!(
                        "more than one address found for {:?}: {:08x?}",
                        self,
                        addresses
                    );
                }

                Ok(addresses)
            }
        }
    }
}
