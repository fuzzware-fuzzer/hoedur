use std::sync::Arc;

use anyhow::{Context, Result};
use parking_lot::Mutex;
use qemu_rs::Address;
use rune::Module;

use crate::hooks::Symbolizer;

/**
 * @Article Script Functions
 * ## Symbolizer
 * `symbolizer::resolve(symbol: &str) -> Result<Address>`
 *
 * Resolve address of `symbol`.
 *
 * Example:
 * ```rune
 * common::patch(symbolizer::resolve("some_function")?, arm::RETURN);
 * ```
 */

/**
 * @Article Script Functions
 * ## Symbolizer
 * `symbolizer::resolve_all(symbol: &str) -> Result<Vec<Address>>`
 *
 * Resolve all addresses of `symbol`.
 *
 * Example:
 * ```rune
 * for addr in symbolizer::resolve_all("some_function")? {
 *     log::info!("some_function = {:08x}", addr);
 * }
 * ```
 */

/**
 * @Article Script Functions
 * ## Symbolizer
 * `symbolizer::lookup(address: Address) -> Option<String>`
 *
 * Lookup symbol for `address`.
 *
 * Example:
 * ```rune
 * let pc = register::read("PC")?;
 * log::info!("{:08x} ({})", pc, symbolizer::lookup(pc)?);
 * ```
 */

/**
 * @Article Script Functions
 * ## Symbolizer
 * `symbolizer::lookup_all(address: Address) -> Vec<String>`
 *
 * Lookup all symbols for `address`.
 *
 * Example:
 * ```rune
 * let pc = register::read("PC")?;
 * for symbol in symbolizer::lookup_all(pc) {
 *     log::info!("{:08x} ({})", pc, symbol);
 * }
 * ```
 */
pub fn module(symbolizer: Arc<Mutex<Symbolizer>>) -> Result<Module> {
    let mut module = Module::with_crate("symbolizer");

    // resolve to first address
    let symbolizer_clone = symbolizer.clone();
    module.function(["resolve"], move |symbol: &str| {
        let result = symbolizer_clone
            .lock()
            .resolve_symbol_with_offset(symbol, 0u32)
            .next()
            .transpose()
            .with_context(|| format!("Failed to resolve symbol {symbol:?}"));
        log::debug!("resolve({:?}) = {:08x?}", symbol, result);

        result.and_then(|address| {
            address.with_context(|| format!("No address found for symbol {symbol:?}"))
        })
    })?;

    // resolve all addresses
    let symbolizer_clone = symbolizer.clone();
    module.function(["resolve_all"], move |symbol: &str| {
        let result: Result<Vec<_>> = symbolizer_clone
            .lock()
            .resolve_symbol_with_offset(symbol, 0u32)
            .map(|result| result.with_context(|| format!("Failed to resolve symbol {symbol:?}")))
            .collect();
        log::debug!("resolve_all({:?}) = {:08x?}", symbol, result);

        result
    })?;

    // lookup symbol
    let symbolizer_clone = symbolizer.clone();
    module.function(["lookup"], move |address: Address| {
        let result = symbolizer_clone
            .lock()
            .lookup_symbol_name(address as u64)
            .map(|name| name.to_string());
        log::debug!("lookup({:08x?}) = {:?}", address, result);

        result.with_context(|| format!("Symbol for address {address:08x} not found"))
    })?;

    // lookup all symbols
    module.function(["lookup_all"], move |address: Address| {
        let result: Vec<_> = symbolizer
            .lock()
            .lookup_symbols(address as u64)
            .map(|symbol| symbol.name_demangled().to_string())
            .collect();
        log::debug!("lookup_all({:08x?}) = {:?}", address, result);

        result
    })?;

    Ok(module)
}
