use std::{borrow::Cow, fmt::Debug, io::Write, mem, ops::Shr};

use anyhow::{Context, Result};
use common::FxHashMap;
use qemu_rs::{Address, Exception, MmioAddress, USize};

use crate::{
    input::{
        value::{InputValue, InputValueType},
        InputContext,
    },
    mmio::{aligned, AccessContext},
    mmio_model::{MmioModel, ReadSize},
    modeling::Modeling,
};

pub type Interrupt = Exception;

pub trait Input: WriteTo {
    fn id(&self) -> usize;
    fn reset(&mut self);
    fn read(&mut self, context: &InputContext) -> Option<Cow<InputValue>>;
}

pub trait WriteTo {
    fn write_to<W: Write>(&self, writer: W) -> anyhow::Result<()>;
    fn write_size(&self) -> Result<u64>;
    fn filename(&self) -> String;
}

#[derive(Debug, Clone)]
pub struct HardwareSnapshot {
    memory: Memory,
}

#[derive(Debug)]
pub struct Hardware<I: Input + Debug> {
    modeling: Modeling,
    memory: Memory,
    input: Option<I>,
    access_log: Vec<InputContext>,
}

#[derive(Debug, Clone)]
pub struct Memory {
    data: FxHashMap<MmioAddress, USize>,
}
#[derive(Debug)]
pub struct HardwareResult<I: Input + Debug> {
    pub input: I,
    pub access_log: Vec<InputContext>,
}

impl<I: Input + Debug> Hardware<I> {
    pub fn new(modeling: Modeling) -> Self {
        Self {
            modeling,
            memory: Memory::new(),
            input: None,
            access_log: vec![],
        }
    }

    pub fn prepare_run(&mut self, input: I) {
        debug_assert!(self.input.is_none());
        debug_assert!(self.access_log.is_empty());

        self.input = Some(input);
    }

    pub fn modeling(&self) -> &Modeling {
        &self.modeling
    }

    pub fn take_result(&mut self) -> Result<HardwareResult<I>> {
        // MMIO access log
        let mut access_log = Vec::with_capacity(self.access_log.capacity());
        mem::swap(&mut self.access_log, &mut access_log);

        Ok(HardwareResult {
            input: self.input.take().context("input file missing")?,
            access_log,
        })
    }

    pub fn input_read(&mut self, context: InputContext) -> Option<Cow<InputValue>> {
        let value = self
            .input
            .as_mut()
            .expect("input file missing")
            .read(&context);

        if value.is_some() {
            self.access_log.push(context);
        }

        value
    }

    pub fn mmio_read(
        &mut self,
        context: &AccessContext,
        size: ReadSize,
    ) -> Result<Option<(USize, bool)>> {
        // unwrap input file
        let input = self.input.as_mut().expect("input file missing");

        // apply the MMIO model
        let model = self
            .modeling
            .get_or_create(context)
            .context("get/create MMIO model failed")?;
        log::trace!("model = {:x?}", model);

        // get input value (either from model or input file)
        let mut input_context = None;
        let value = match model {
            Some(MmioModel::Passthrough { initial_value }) => {
                let mmio = context.mmio();
                Some(
                    self.memory
                        .read(mmio.addr(), size)
                        .unwrap_or(*initial_value),
                )
            }
            Some(MmioModel::Constant { value }) => Some(*value),
            Some(MmioModel::Set { values }) => {
                let context =
                    InputContext::from_access(context, InputValueType::Choice(values.len() as u8));
                let value = input
                    .read(&context)
                    .map(|input_value| match input_value.as_ref() {
                        InputValue::Choice { index, .. } => values[*index as usize],
                        _ => unreachable!("invalid InputValue type"),
                    });

                input_context = Some(context);
                value
            }
            Some(MmioModel::BitExtract(be)) => {
                let context = InputContext::from_access(context, InputValueType::Bits(be.bits()));
                let value = input
                    .read(&context)
                    .map(|input_value| match input_value.as_ref() {
                        InputValue::Bits { value, .. } => be.apply(*value),
                        _ => unreachable!("invalid InputValue type"),
                    });

                input_context = Some(context);
                value
            }
            None => {
                let context = InputContext::from_access(context, size.into());
                let value = input
                    .read(&context)
                    .map(|input_value| match input_value.as_ref() {
                        InputValue::Byte(value) => *value as u32,
                        InputValue::Word(value) => *value as u32,
                        InputValue::DWord(value) => *value,
                        _ => unreachable!("invalid InputValue type"),
                    });

                input_context = Some(context);
                value
            }
        };
        log::trace!("[READ] {:x?} => {:x?}", context, value);

        Ok(value.map(|value| {
            // track mmio accesses
            let input_value = if let Some(context) = input_context {
                self.access_log.push(context);
                true
            } else {
                false
            };

            (value, input_value)
        }))
    }

    pub fn mmio_write(&mut self, context: &AccessContext, data: USize, size: ReadSize) {
        let mmio = context.mmio();
        if self.modeling.is_passthrough(mmio.addr()) {
            // TODO: overlapping initial_values with values != 0 can cause issues
            // this should never happen with fuzzware models, but a warning/error would be nice
            self.memory.write(mmio.addr(), data, size);
        }
        log::trace!("[WRITE] {:x?} data: {:x}", context, data);
    }

    pub fn snapshot_create(&self) -> HardwareSnapshot {
        HardwareSnapshot {
            memory: self.memory.clone(),
        }
    }

    pub fn snapshot_restore(&mut self, snapshot: &HardwareSnapshot) {
        let HardwareSnapshot { memory } = snapshot;

        self.memory = memory.clone();
    }
}

impl Memory {
    fn new() -> Self {
        Self {
            data: FxHashMap::default(),
        }
    }

    fn read(&self, address: Address, size: ReadSize) -> Option<USize> {
        let value = self
            .data
            .get(&aligned(address))
            .map(|raw_data| raw_data.shr(memory_shift(address)) & size.mask());
        log::trace!(
            "read: address = {:08x?}, size = {:?}, value = {:08x?}",
            address,
            size,
            value,
        );

        value
    }

    fn write(&mut self, address: Address, value: USize, size: ReadSize) {
        let shift = memory_shift(address);
        let mask = size.mask() << shift;
        let old_data = self.data.get(&aligned(address)).copied().unwrap_or(0);
        let other_data = old_data & !mask;
        let new_data = ((value << shift) & mask) | other_data;
        log::trace!(
            "write: address = {:08x?}, size = {:?}, value = {:08x?}, old_data = {:08x?}, new_data = {:08x?}",
            address,
            size,
            value,
            old_data,
            new_data,
        );

        self.data.insert(aligned(address), new_data);
    }
}

fn memory_shift(address: Address) -> u32 {
    let byte_offset = address - aligned(address);
    byte_offset * u8::BITS
}
