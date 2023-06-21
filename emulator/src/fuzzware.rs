use std::{
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use common::fs::{bufreader, relative_path};
use frametracer::symbolizer::{Object, Symbolizer};
use glob::glob;
use itertools::Itertools;
use modeling::fuzzware::config::{
    DisabledInterrupt, FuzzMode, FuzzwareConfig, Handler, HandlerWrapper, IndexMap,
    InterruptMode as FuzzwareInterruptMode, InterruptTrigger, MemoryMap as FuzzwareMemoryMap, Nvic,
    Target,
};
use qemu_rs::{
    board::Board,
    memory::{FileData, MemoryMap, MemoryPermission, MemoryRegion, MemoryType},
    Address,
};

use crate::{
    hooks::{
        debug::{DebugHook, DebugHookOption, DebugHookType},
        HookTarget,
    },
    interrupt::{
        CustomInterruptTrigger, InterruptMode, TargetInterruptConfig, TargetInterruptInterval,
        TargetInterruptTrigger,
    },
    limits::TargetLimits,
    EmulatorTargetConfig, ExitHook,
};

const PAGE_SIZE: Address = qemu_rs::memory::PAGE_SIZE as Address;

impl EmulatorTargetConfig {
    pub fn from_fuzzware(fuzzware: FuzzwareConfig, working_directory: &Path) -> Result<Self> {
        let symbols = &fuzzware.symbols;
        let limits = fuzzware.limits.map(TargetLimits::from_fuzzware);

        // board config
        let mut board = Board::default();
        let mut auto_is_entry = true;
        #[cfg(feature = "arm")]
        if let Some(nvic) = &fuzzware.nvic {
            // initial vtor
            if let Some(vtor) = nvic.vtor {
                board.set_init_nsvtor(vtor);
                auto_is_entry = false;
            }

            // number of irq's
            if let Some(num_vecs) = nvic.num_vecs {
                board.set_num_irq(num_vecs as u32);
            }
        }
        #[cfg(feature = "arm")]
        if let Some(use_systick) = fuzzware.use_systick {
            board.set_systick(use_systick);
        }

        // convert memory models
        let fuzzware_memory_maps = fuzzware.memory_map.context("memory maps missing")?;
        let mut objects = IndexMap::default();
        let memory_maps = fuzzware_memory_maps
            .into_iter()
            .map(|(name, map)| {
                let debug = format!("{name}: {map:x?}");
                convert_memory_map(
                    name,
                    map,
                    &mut auto_is_entry,
                    &mut board,
                    &mut objects,
                    working_directory,
                )
                .with_context(|| debug)
            })
            .collect::<Result<Vec<_>>>()
            .context("Failed to convert memory maps")?
            .into_iter()
            .flatten()
            .collect();
        let new_objects = objects.keys().cloned().collect_vec();
        let symbolizer = Symbolizer::new(objects.into_values().collect_vec());

        // convert interrupt
        let use_nvic = fuzzware.use_systick.unwrap_or(true) || fuzzware.use_nvic.unwrap_or(true);
        let interrupt = if use_nvic {
            let symbolizer_ref = &symbolizer;
            fuzzware
                .interrupt_triggers
                .map(|config| {
                    convert_interrupt(
                        config,
                        &fuzzware.nvic,
                        symbols,
                        symbolizer_ref,
                        &new_objects,
                    )
                })
                .transpose()?
                .flatten()
        } else {
            if fuzzware
                .interrupt_triggers
                .map(|irq| irq.len())
                .unwrap_or(0)
                > 0
            {
                log::warn!("interrupt_triggers are ignored due to disabled use_nvic");
            }

            Some(TargetInterruptConfig::new(
                InterruptMode::Disabled,
                TargetInterruptTrigger::default(),
                None,
                None,
            ))
        };

        // convert mmio models
        let mmio_models = fuzzware
            .mmio_models
            .map(|models| models.convert().collect::<Vec<_>>());

        // convert exit hooks (and resolve symbols)
        let mut exit_hooks = vec![];
        if let Some(exit_at) = fuzzware.exit_at {
            for (name, target) in exit_at {
                // exit hook target
                let target = match target {
                    Some(target) => target,
                    None => serde_yaml::from_str(&name).with_context(|| {
                        format!("{name}: Failed to parse exit_at name as symbol/address")
                    })?,
                };

                // add exit hook
                if let Some(target) = resolve_symbol(target, symbols, &symbolizer, &new_objects)? {
                    exit_hooks.push(ExitHook::new(Some(name), target));
                }
            }
        }

        // convert debug hooks (and resolve symbols)
        let mut patches = vec![];
        let mut debug_hooks = vec![];
        if let Some(handlers) = fuzzware.handlers {
            for (name, handler) in handlers {
                // handler target
                let parse_symbol = |name: &str| {
                    serde_yaml::from_str(name).with_context(|| {
                        format!("{name}: Failed to parse handler name as symbol/address")
                    })
                };
                let target = match &handler {
                    Some(HandlerWrapper::Shorthand(name)) => parse_symbol(name)?,
                    Some(HandlerWrapper::Handler(Handler {
                        address: Some(target),
                        ..
                    })) => target.clone(),
                    _ => parse_symbol(&name)?,
                };

                // convert handler to hooks
                if let Some(target) = resolve_symbol(target, symbols, &symbolizer, &new_objects)? {
                    let mut debug_hook = |hook_type| {
                        debug_hooks.push(DebugHook::new(
                            Some(name.clone()),
                            hook_type,
                            DebugHookOption::default(),
                            target.clone(),
                        ))
                    };
                    let mut patch = |bytes| patches.push(format_patch(&target, bytes, &name));

                    // add exit return hook
                    match &handler {
                        // skip return is disabled (needs to be specifically set)
                        Some(HandlerWrapper::Handler(Handler { do_return, .. })) if !do_return => {}
                        _ => patch("arm::RETURN"),
                    }

                    // convert handler to known debug hooks
                    if let Some(HandlerWrapper::Handler(Handler {
                        handler: Some(handler),
                        ..
                    })) = &handler
                    {
                        // match debug hooks
                        match handler.as_str() {
                            "fuzzware_harness.user_hooks.generic.stdio.puts" => {
                                debug_hook(DebugHookType::Puts)
                            }
                            "fuzzware_harness.user_hooks.generic.stdio.printf" => {
                                debug_hook(DebugHookType::Printf)
                            }
                            "native.return_0x0" => patch("arm::RETURN_0"),
                            "native.return_0x1" => patch("arm::RETURN_1"),
                            /* handler if handler.starts_with("native.inline_asm_") => {
                                TODO: support inline_asm
                            } */
                            _ => {
                                log::warn!("{}: Handler '{}' is not supported!", name, handler);
                            }
                        }
                    }
                }
            }
        }

        // catch unsupported options
        if fuzzware.entry_point.is_some() {
            log::warn!("entry_point is not supported");
        }
        if fuzzware.initial_sp.is_some() {
            log::warn!("initial_sp is not supported");
        }
        if fuzzware.boot.is_some() {
            log::warn!("boot is not supported");
        }
        if fuzzware.use_exit_at.is_some() {
            log::warn!("use_exit_at is not supported");
        }
        if fuzzware.timers.is_some() {
            log::warn!("timers is not supported");
        }

        Ok(Self {
            cpu: None,
            board: (board != Board::default()).then_some(board),
            limits,
            interrupt,
            memory_maps,
            mmio_models,
            exit_hooks: (!exit_hooks.is_empty()).then_some(exit_hooks),
            debug_hooks: (!debug_hooks.is_empty()).then_some(debug_hooks),
            symbols: (!new_objects.is_empty()).then_some(new_objects),
            script: (!patches.is_empty()).then(|| {
                format!(
                    "pub fn main(api) {{\n  api.on_init(on_init);\n}}\n\nfn on_init() {{\n  {}\n}}",
                    patches.join("\n  ")
                )
            }),
        })
    }

    pub fn script(&self) -> Option<&str> {
        self.script.as_deref()
    }
}

fn format_patch(target: &HookTarget, bytes: &str, name: &String) -> String {
    match target {
        HookTarget::BasicBlock { pc } => {
            format!("common::patch_address({pc:#X?}, {bytes}); // {name}")
        }
        HookTarget::Function {
            symbol,
            offset: None,
        } => format!("common::patch_function({symbol:?}, {bytes});"),
        HookTarget::Function {
            symbol,
            offset: Some(offset),
        } => {
            format!("common::patch_function(symbolizer::resolve({symbol:?})? + {offset}, {bytes});")
        }
    }
}

fn convert_interrupt(
    config: IndexMap<String, InterruptTrigger>,
    nvic: &Option<Nvic>,
    symbols: &Option<IndexMap<Address, String>>,
    symbolizer: &Symbolizer,
    new_objects: &[PathBuf],
) -> Result<Option<TargetInterruptConfig>> {
    let mut mode = None;
    let mut allowlist = None;
    let mut on_infinite_sleep = true;
    let mut interval = None;
    let mut custom = None;

    for (name, trigger) in config {
        let old = match &trigger.mode {
            FuzzwareInterruptMode::Fixed { irq } => {
                log::warn!(
                    "{}: interrupt mode fixed is not supported, using round-robin with allowlist",
                    name
                );

                if allowlist.is_some() {
                    log::warn!(
                        "{}: multiple fixed interrupts are merged in allowlist ({:x?})",
                        name,
                        trigger
                    );
                }
                allowlist.get_or_insert_with(Vec::new).push(*irq);

                mode.replace(InterruptMode::RoundRobin)
            }
            FuzzwareInterruptMode::FuzzMode { fuzz_mode } => match fuzz_mode {
                FuzzMode::Fuzzed => mode.replace(InterruptMode::Fuzzed),
                FuzzMode::RoundRobin => {
                    if let Some(trigger_interval) = trigger.interval {
                        let old =
                            interval.replace(TargetInterruptInterval::BasicBlock(trigger_interval));
                        if old.is_some() {
                            log::warn!(
                                "{}: multiple interrupt intervals are not supported ({:x?})",
                                name,
                                trigger
                            );
                        }
                    }

                    mode.replace(InterruptMode::RoundRobin)
                }
            },
        };
        if old.is_some() {
            log::warn!(
                "{}: multiple interrupt configs are not supported ({:x?})",
                name,
                trigger
            );
        }

        if let Some(address) = trigger.address {
            log::warn!(
                "{name}: address is not supported, adding custom trigger at {address:?} and disabling on-infinite-sleep and interval instead"
            );

            on_infinite_sleep = false;
            interval = Some(TargetInterruptInterval::Enabled(false));

            if let Some(target) = resolve_symbol(address, symbols, symbolizer, new_objects)? {
                custom
                    .get_or_insert_with(Vec::new)
                    .push(CustomInterruptTrigger::new(Some(name.clone()), target));
            }
        }
        if trigger.num_pends.is_some() {
            log::warn!("{}: num_pends is not supported", name);
        }
        if trigger.num_skips.is_some() {
            log::warn!("{}: num_skips is not supported", name);
        }
    }

    Ok(if let Some(mode) = mode {
        Some(TargetInterruptConfig::new(
            mode,
            interval
                .map(|interval| TargetInterruptTrigger::new(on_infinite_sleep, interval, custom))
                .unwrap_or_default(),
            allowlist,
            nvic.as_ref()
                .and_then(|nvic| nvic.disabled_irqs.as_deref())
                .map(|irqs| irqs.iter().copied().map(DisabledInterrupt::into).collect()),
        ))
    } else {
        log::warn!("no supported interrupt config found");
        None
    })
}

fn convert_memory_map(
    name: String,
    map: FuzzwareMemoryMap,
    auto_is_entry: &mut bool,
    #[cfg_attr(not(feature = "arm"), allow(unused_variables))] board: &mut Board,
    objects: &mut IndexMap<PathBuf, Object>,
    working_directory: &Path,
) -> Result<Vec<MemoryMap>> {
    // page alinged start
    let address_offset = map.address % PAGE_SIZE;
    let load_offset = map.load_offset.unwrap_or(0);
    let offset = address_offset + load_offset;
    let address = map.address - address_offset;

    if address != map.address {
        log::info!(
            "{}: memory map start aligned from {:#x?} to {:#x?}",
            name,
            map.address,
            address
        );
    }

    // page alinged size
    let orig_size = map.size;
    let aligned_size = map.size + address_offset;
    let pages = aligned_size / PAGE_SIZE;
    let padding = (aligned_size % PAGE_SIZE) > 0;
    let size = if padding { pages + 1 } else { pages } * PAGE_SIZE;

    if size != map.size {
        log::info!(
            "{}: memory map size aligned from {:#x?} to {:#x?}",
            name,
            orig_size,
            size
        );
    }

    // verify permissions string
    let permission = map.permissions.trim();
    if permission.len() != 3 {
        bail!(
            "Unsupported permission format {:?} for memory map {}: {:#x?}",
            permission,
            name,
            map
        );
    }

    // filter Fuzzware NVIC region
    if map.address == 0xfffff000 && map.size == 0x1000 && permission == "--x" {
        log::info!("Filter Fuzzware specific memory map {name}: {map:x?}");
        return Ok(vec![]);
    }
    // replace Fuzzware generic Private/Vendor mmio memory region
    if map.address == 0xe0000000 && map.size == 0x10000000 && permission == "rw-" {
        log::info!("Filter/Replace Fuzzware specific memory map {name}: {map:x?}");

        // ITM 0xE0000000, DWT 0xE0001000, BPU 0xE0002000, CTI 0xE0042000
        // Vendor 0xE0100000-0xFFFFFFFF
        let memory_maps = [
            ("ITM_DWT_BPU", 0xE0000000, 0x3000),
            ("CTI", 0xE0042000, 0x1000),
        ]
        .into_iter()
        .map(|(name, address, size)| {
            MemoryMap::new(
                Some(name.into()),
                MemoryRegion::new(address, size),
                None,
                None,
                None,
                MemoryType::Mmio,
            )
        })
        .collect();

        return Ok(memory_maps);
    }

    // memory type
    let memory_type = if name.starts_with("mmio") {
        match permission {
            "rw-" => {}
            _ => {
                bail!(
                    "Unsupported permissions {:?} for MMIO region {}: {:#x?}",
                    permission,
                    name,
                    map
                )
            }
        }

        MemoryType::Mmio
    } else {
        match &permission[..2] {
            "r-" => MemoryType::Rom,
            "rw" => MemoryType::Ram,
            _ => {
                bail!(
                    "Unsupported permissions {:?} for memory region {}: {:#x?}",
                    permission,
                    name,
                    map
                )
            }
        }
    };

    // permissions / executable
    let executable = &permission[2..] == "x";
    let permission =
        (memory_type.executable() != executable).then(|| MemoryPermission::new(executable, None));

    // file backend
    let file_data = map
        .file
        .as_ref()
        .map(|file_glob| {
            let mut paths: Vec<_> = glob(&format!("{}/{}", working_directory.display(), file_glob))
                .with_context(|| format!("glob for file path {file_glob:?} failed"))?
                .collect();

            // verify only one file is found
            if paths.len() > 1 {
                bail!(
                    "more than one file was found for {:?} in wokring directory {:?}: {:?}",
                    file_glob,
                    working_directory,
                    paths
                );
            }

            // get first (and only) file
            let path = paths
                .pop()
                .with_context(|| {
                    format!(
                        "file {file_glob:?} not found in wokring directory {working_directory:?}"
                    )
                })?
                .with_context(|| format!("glob entry for file path {file_glob:?} is invalid"))?;

            // get file size
            let file_size = path
                .metadata()
                .with_context(|| format!("Failed to get metadata for file {path:?}"))?
                .len();
            let seek = map.file_offset.unwrap_or(0);
            let length = file_size as Address - seek;

            // make path relative to working dir
            let path = relative_path(&path, working_directory)?;

            Ok(FileData::new(
                (offset != 0).then_some(offset),
                path,
                (seek != 0).then_some(seek),
                (orig_size < length).then_some(orig_size),
            ))
        })
        .transpose()?;

    // search for symbol files
    if let Some(file_glob) = map.file {
        println!("file_glob = {file_glob:?}");

        let mut symbols_glob = PathBuf::from(file_glob);
        symbols_glob.set_extension("elf").to_string();

        println!("symbols_glob = {symbols_glob:?}");

        match glob(&format!(
            "{}/{}",
            working_directory.display(),
            symbols_glob.display()
        ))
        .with_context(|| format!("glob for file path {symbols_glob:?} failed"))
        {
            Ok(glob) => {
                for result in glob {
                    let path = match result {
                        Ok(path) => path,
                        Err(err) => {
                            log::warn!("Failed to search for symbol files: {:?}", err);
                            continue;
                        }
                    };

                    // make path relative to working dir
                    let relative = relative_path(&path, working_directory)?;

                    // add only once
                    if objects.contains_key(&relative) {
                        continue;
                    }

                    // try to read symbols file
                    let mut bytes = vec![];
                    match bufreader(&path)
                        .and_then(|mut reader| {
                            reader
                                .read_to_end(&mut bytes)
                                .context("Failed to read file")
                        })
                        .and_then(|_| {
                            Object::from_bytes(&bytes).context("Failed to parse object file")
                        }) {
                        Ok(object) => {
                            objects.insert(relative, object);
                        }
                        Err(err) => {
                            log::warn!("Failed to read symbol file {:?}: {:?}", path, err)
                        }
                    }
                }
            }
            Err(err) => log::warn!("Failed to search for symbol files: {:?}", err),
        }
    }

    // verify is_entry / use alias for ivt on other memory map
    let is_entry = map
        .is_entry
        .unwrap_or_else(|| file_data.is_some() && *auto_is_entry);

    if is_entry {
        // set non-default nsvtor
        if map.address != 0x0 {
            #[cfg(feature = "arm")]
            board.set_init_nsvtor(map.address);
        }

        // disable auto IVT
        *auto_is_entry = false;
    }

    // verify ivt_offset
    if !is_entry && map.ivt_offset.is_some() {
        log::warn!("{}: ivt_offset is not supported for !is_entry", name);
    } else if is_entry && map.ivt_offset > Some(0x0) {
        log::warn!("{}: ivt_offset > 0 is not supported", name);
    }

    Ok(vec![MemoryMap::new(
        Some(name),
        MemoryRegion::new(address, size),
        None,
        permission,
        file_data,
        memory_type,
    )])
}

fn resolve_symbol(
    target: Target,
    symbols: &Option<IndexMap<Address, String>>,
    symbolizer: &Symbolizer,
    new_objects: &[PathBuf],
) -> Result<Option<HookTarget>> {
    let address = match target {
        Target::Address(address) => HookTarget::BasicBlock {
            pc: fix_address(address),
        },
        Target::Symbol(symbol) => {
            let parts: Vec<_> = symbol.split('+').collect();

            let symbol = parts[0];
            let offset = match parts.get(1) {
                Some(offset) => str::parse::<Address>(offset).with_context(|| {
                    format!("Failed to parse symbol offset {offset:?} in symbol {symbol:?}")
                })?,
                None => 0,
            };

            if let Some(symbols) = symbols {
                if let Some(address) = symbols
                    .iter()
                    .find(|(_, value)| *value == symbol)
                    .map(|(address, _)| address)
                {
                    // fix thumb-bit
                    let address = fix_address(*address);

                    // find symbol
                    let new_address = symbolizer
                        .resolve_symbol_with_offset(symbol, 0)
                        .next()
                        .transpose()?;
                    if new_address.is_none() {
                        log::warn!(
                            "Failed to resolve symbol {:?} in new objects files: {:?}",
                            symbol,
                            new_objects
                                .iter()
                                .map(|path| path.display())
                                .collect::<Vec<_>>()
                        );
                    }

                    // verify smybols match
                    if new_address == Some(address as u64) {
                        HookTarget::Function {
                            symbol: symbol.into(),
                            offset: (offset != 0).then_some(offset),
                        }
                    } else {
                        log::warn!(
                            "Failed to match address resolve for symbol {:?}: fuzzware = {:08?}, hoedur = {:08?}",
                            symbol,
                            address,
                            new_address
                        );

                        HookTarget::BasicBlock {
                            pc: address + offset,
                        }
                    }
                } else {
                    log::warn!(
                        "Failed to resolve symbol {:?}: not found in symbol table",
                        symbol
                    );
                    return Ok(None);
                }
            } else {
                bail!(
                    "Failed to resolve symbol {:?}: symbol table missing",
                    symbol
                )
            }
        }
    };

    Ok(Some(address))
}

fn fix_address(address: Address) -> Address {
    // ARM may have thumb-bit set, this is PITA for everything - just remove it
    #[cfg(feature = "arm")]
    let address = address & !(1 as Address);

    address
}
