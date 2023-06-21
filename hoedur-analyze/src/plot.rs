use std::fmt;

use anyhow::Result;
use std::io::Write;

pub struct PlotWriter<'a, W: Write> {
    first: bool,
    output: &'a mut W,
}

impl<'a, W: Write> PlotWriter<'a, W> {
    pub fn new(output: &'a mut W) -> Result<Self> {
        writeln!(output, "{{")?;

        Ok(Self {
            first: true,
            output,
        })
    }

    pub fn plot<X: fmt::Debug, Y: fmt::Debug>(
        &mut self,
        name: &str,
        data: &[(X, Y)],
    ) -> Result<()> {
        if self.first {
            self.first = false;
        } else {
            writeln!(self.output, ",")?;
        }
        write!(self.output, "{name:?}: [")?;

        let mut first = true;
        for (x, y) in data {
            if first {
                first = false;
            } else {
                write!(self.output, ", ")?;
            }

            write!(self.output, "{{ \"x\": {x:?}, \"y\": {y:?} }}")?;
        }

        write!(self.output, "]")?;
        Ok(())
    }

    pub fn finish(self) -> Result<()> {
        // finish JSON file
        writeln!(self.output)?;
        write!(self.output, "}}")?;
        Ok(())
    }
}
