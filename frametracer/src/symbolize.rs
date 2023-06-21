use std::{fmt, sync::Arc};

use symbolizer::Symbolizer;

use crate::{Address, Result};

pub struct WithSymbolizer<'a, T: DisplaySymbolized> {
    inner: &'a T,
    symbolizer: Option<&'a Symbolizer>,
}

impl<'a, T: DisplaySymbolized> fmt::Display for WithSymbolizer<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.symbolizer {
            Some(symbolizer) => self.inner.fmt_symbolized(f, Some(symbolizer)),
            None => self.inner.fmt_symbolized(f, None),
        }
        .map_err(|_| fmt::Error)
    }
}

pub struct WithoutSymbolizer<'a, T: DisplaySymbolized> {
    inner: &'a T,
}

impl<'a, T: DisplaySymbolized> fmt::Display for WithoutSymbolizer<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt_symbolized(f, None).map_err(|_| fmt::Error)
    }
}

pub trait DisplaySymbolized {
    fn fmt_symbolized(
        &self,
        f: &mut fmt::Formatter<'_>,
        symbolizer: Option<&Symbolizer>,
    ) -> Result<()>;
}

pub trait Symbolizable: Sized + DisplaySymbolized {
    fn display(&self) -> WithoutSymbolizer<Self>;
    fn display_symbolizer<'a>(
        &'a self,
        symbolizer: Option<&'a Symbolizer>,
    ) -> WithSymbolizer<'a, Self>;

    fn with_symbolizer<'a>(&'a self, symbolizer: &'a Symbolizer) -> WithSymbolizer<'a, Self> {
        self.display_symbolizer(Some(symbolizer))
    }
}

impl<T: DisplaySymbolized> Symbolizable for T {
    fn display(&self) -> WithoutSymbolizer<Self> {
        WithoutSymbolizer { inner: self }
    }

    fn display_symbolizer<'a>(
        &'a self,
        symbolizer: Option<&'a Symbolizer>,
    ) -> WithSymbolizer<'a, Self> {
        WithSymbolizer {
            inner: self,
            symbolizer,
        }
    }
}

pub fn fmt_address(
    f: &mut fmt::Formatter<'_>,
    symbolizer: Option<&Symbolizer>,
    address: Address,
    unknown: bool,
) -> Result<()> {
    Ok(match lookup_name(symbolizer, address)? {
        Some(name) => write!(f, "{address:08x} ({name})"),
        None if unknown => write!(f, "{address:08x} <unknown>"),
        None => write!(f, "{address:08x}"),
    }?)
}

pub fn lookup_name(symbolizer: Option<&Symbolizer>, address: u32) -> Result<Option<Arc<str>>> {
    if let Some(symbolizer) = symbolizer {
        symbolizer.lookup_name(address as u64).map_err(Into::into)
    } else {
        Ok(None)
    }
}
