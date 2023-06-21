use std::{
    fmt::{self, Debug},
    io::{self, Read, Write},
    ops::Range,
};

use serde::{Deserialize, Serialize};
use symbolizer::Symbolizer;

use crate::{
    errors::Result, symbolize::fmt_address, Address, DisplaySymbolized, Error, ExceptionNum, USize,
};

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq, Clone)]
pub struct Trace {
    pub events: Vec<TraceEvent>,
}

pub struct TraceIter<'a, S: Read> {
    stream: &'a mut S,
    events: Vec<TraceEvent>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum TraceEvent {
    Run(Run),
    BasicBlock(BasicBlock),
    Exception(Exception),
    ExceptionExit,
    Access(Access),
    Stop,
    TaskSwitch(TaskSwitch),
    Instruction(Instruction),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Run {
    pub id: usize,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct BasicBlock {
    pub pc: Address,
    pub ra: Address,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Instruction {
    pub pc: Address,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Exception {
    pub pc: Address,
    pub exception: ExceptionNum,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct TaskSwitch {
    pub previous: Address,
    pub next: Address,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Access {
    pub target: AccessTarget,
    pub access_type: AccessType,
    pub size: u8,
    pub pc: Address,
    pub address: Address,
    pub value: USize,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum AccessTarget {
    Ram,
    Mmio,
    Stack,
    Rom,
}
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum AccessType {
    Read,
    Write,
}

impl DisplaySymbolized for Trace {
    fn fmt_symbolized(
        &self,
        f: &mut fmt::Formatter<'_>,
        symbolizer: Option<&Symbolizer>,
    ) -> Result<()> {
        for event in self.events.iter() {
            event.fmt_symbolized(f, symbolizer)?;
            writeln!(f)?;
        }

        Ok(())
    }
}

impl DisplaySymbolized for TraceEvent {
    fn fmt_symbolized(
        &self,
        f: &mut fmt::Formatter<'_>,
        symbolizer: Option<&symbolizer::Symbolizer>,
    ) -> crate::Result<()> {
        match self {
            TraceEvent::Run(event) => event.fmt_symbolized(f, symbolizer),
            TraceEvent::BasicBlock(event) => event.fmt_symbolized(f, symbolizer),
            TraceEvent::Instruction(event) => event.fmt_symbolized(f, symbolizer),
            TraceEvent::Exception(event) => event.fmt_symbolized(f, symbolizer),
            TraceEvent::ExceptionExit => write!(f, "ExceptionExit").map_err(Error::from),
            TraceEvent::TaskSwitch(event) => event.fmt_symbolized(f, symbolizer),
            TraceEvent::Access(event) => event.fmt_symbolized(f, symbolizer),
            TraceEvent::Stop => write!(f, "Stop").map_err(Error::from),
        }
    }
}

impl DisplaySymbolized for Run {
    fn fmt_symbolized(
        &self,
        f: &mut fmt::Formatter<'_>,
        _symbolizer: Option<&Symbolizer>,
    ) -> Result<()> {
        write!(f, "Run [ id: {} ]", self.id)?;
        Ok(())
    }
}

impl DisplaySymbolized for BasicBlock {
    fn fmt_symbolized(
        &self,
        f: &mut fmt::Formatter<'_>,
        symbolizer: Option<&Symbolizer>,
    ) -> Result<()> {
        let unknown = symbolizer.is_some();
        write!(f, "BasicBlock [ pc: ")?;
        fmt_address(f, symbolizer, self.pc, unknown)?;
        write!(f, ", ra: ")?;
        fmt_address(f, symbolizer, self.ra, unknown)?;
        write!(f, " ]")?;
        Ok(())
    }
}

impl DisplaySymbolized for Instruction {
    fn fmt_symbolized(
        &self,
        f: &mut fmt::Formatter<'_>,
        symbolizer: Option<&Symbolizer>,
    ) -> Result<()> {
        let unknown = symbolizer.is_some();
        write!(f, "Instruction [ pc: ")?;
        fmt_address(f, symbolizer, self.pc, unknown)?;
        write!(f, " ]")?;
        Ok(())
    }
}

impl fmt::Display for Exception {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Exception [ pc: {:08x}, exception: {:08x} ]",
            self.pc, self.exception
        )
    }
}

impl DisplaySymbolized for Exception {
    fn fmt_symbolized(
        &self,
        f: &mut fmt::Formatter<'_>,
        symbolizer: Option<&Symbolizer>,
    ) -> Result<()> {
        let unknown = symbolizer.is_some();
        write!(f, "Exception [ pc: ")?;
        fmt_address(f, symbolizer, self.pc, unknown)?;
        write!(f, ", exception: {} ]", self.exception)?;
        Ok(())
    }
}

impl DisplaySymbolized for TaskSwitch {
    fn fmt_symbolized(
        &self,
        f: &mut fmt::Formatter<'_>,
        symbolizer: Option<&Symbolizer>,
    ) -> Result<()> {
        write!(f, "TaskSwitch [ previous: ")?;
        fmt_address(f, symbolizer, self.previous, false)?;
        write!(f, ", next: ")?;
        fmt_address(f, symbolizer, self.next, false)?;
        write!(f, " ]")?;
        Ok(())
    }
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} Access ({:?}) [ pc: {:08x}, size: {}, address: {:08x}, value: {:08x} ]",
            match self.target {
                AccessTarget::Rom => "ROM",
                AccessTarget::Ram => "RAM",
                AccessTarget::Mmio => "MMIO",
                AccessTarget::Stack => "Stack",
            },
            self.access_type,
            self.pc,
            self.size,
            self.address,
            self.value,
        )
    }
}

impl DisplaySymbolized for Access {
    fn fmt_symbolized(
        &self,
        f: &mut fmt::Formatter<'_>,
        symbolizer: Option<&Symbolizer>,
    ) -> Result<()> {
        let unknown = symbolizer.is_some();
        write!(
            f,
            "{} Access ({:?}) [ pc: ",
            match self.target {
                AccessTarget::Rom => "ROM",
                AccessTarget::Ram => "RAM",
                AccessTarget::Mmio => "MMIO",
                AccessTarget::Stack => "Stack",
            },
            self.access_type,
        )?;
        fmt_address(f, symbolizer, self.pc, unknown)?;
        write!(f, ", size: {}, address: ", self.size)?;
        fmt_address(f, symbolizer, self.address, false)?;
        write!(f, ", value: ")?;
        fmt_address(f, symbolizer, self.value, false)?;
        write!(f, " ]").map_err(Error::from)
    }
}

impl<'a, S: Read> TraceIter<'a, S> {
    pub fn new(stream: &'a mut S) -> Self {
        TraceIter {
            stream,
            events: vec![],
        }
    }
}

impl<'a, S: Read> Iterator for TraceIter<'a, S> {
    type Item = Result<Trace>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match TraceEvent::read_from(&mut self.stream) {
                Err(err) => return Some(Err(err)),
                Ok(Some(event)) => {
                    let end = event == TraceEvent::Stop;

                    self.events.push(event);

                    if end {
                        break;
                    }
                }
                Ok(None) => break,
            }
        }

        if !self.events.is_empty() {
            let mut events = vec![];
            std::mem::swap(&mut self.events, &mut events);
            Some(Ok(Trace { events }))
        } else {
            None
        }
    }
}

impl Trace {
    pub fn read_from<S: Read>(stream: &mut S) -> Result<Vec<Self>> {
        let mut traces = vec![];
        let mut events = vec![];

        while let Some(event) = TraceEvent::read_from(&mut *stream)? {
            let end = event == TraceEvent::Stop;

            events.push(event);

            if end {
                let mut tmp_events = vec![];
                std::mem::swap(&mut events, &mut tmp_events);
                traces.push(Self { events: tmp_events })
            }
        }

        traces.push(Self { events });

        Ok(traces)
    }

    pub fn write_to<W: Write>(&self, stream: &mut W) -> Result<()> {
        for event in &self.events {
            event.write_to(&mut *stream)?;
        }

        Ok(())
    }
}

impl TraceEvent {
    pub fn read_from<S: Read>(mut stream: S) -> Result<Option<Self>> {
        bincode::deserialize_from(&mut stream)
            .map(Some)
            .or_else(|err| match &*err {
                bincode::ErrorKind::Io(io_err) => {
                    if io_err.kind() == io::ErrorKind::UnexpectedEof {
                        Ok(None)
                    } else {
                        Err(err.into())
                    }
                }
                _ => Err(err.into()),
            })
    }

    pub fn write_to<W: Write>(&self, stream: &mut W) -> Result<()> {
        Ok(bincode::serialize_into(stream, self)?)
    }
}

impl Access {
    pub fn address_range(&self) -> Range<Address> {
        self.address..self.address.saturating_add(self.size as Address)
    }
}
