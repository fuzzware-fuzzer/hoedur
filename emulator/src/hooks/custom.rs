use std::{
    convert::TryFrom,
    ffi::CStr,
    fmt::Debug,
    fs,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use ::common::{
    exit::{EXIT, TERM},
    FxHashMap,
};
use anyhow::{Context, Result};
use endiannezz::Primitive;
use frametracer::AccessType;
use modeling::{hardware::Interrupt, mmio::aligned};
use parking_lot::{const_mutex, Mutex};
use qemu_rs::{memory::MemoryType, qcontrol, qcontrol_mut, Address, MmioAddress, Register, USize};
use rune::{
    macros::{quote, FormatArgs, MacroContext, Quote, TokenStream},
    parse::Parser,
    runtime::{Function, RuntimeContext, VmError},
    termcolor::{ColorChoice, StandardStream},
    Any, Diagnostics, Module, Source, SourceId, Sources, Unit, Value, Vm,
};

use crate::debug::CustomHook;

use super::Symbolizer;

#[cfg(feature = "arm")]
mod arm;
mod common;
mod symbolizer;

pub(crate) static STOP: AtomicBool = AtomicBool::new(false);
pub(crate) static BUGS: Mutex<Option<Vec<Bug>>> = const_mutex(None);
pub type Bug = String;

#[derive(Debug)]
pub struct HookRuntime {
    scripts: Vec<HookScript>,
}

#[derive(Debug)]
pub struct HookScript {
    api: ScriptApi,
    script: SourceId,
    sources: Sources,
}

#[derive(Debug, Default, Any)]
struct ScriptApi {
    init: ScriptHooks,
    prepare_run: ScriptHooks,
    basic_block: FxHashMap<BasicBlockFilter, ScriptHooks>,
    instruction: FxHashMap<InstructionFilter, ScriptHooks>,
    interrupt: FxHashMap<InterruptFilter, ScriptHooks>,
    memory_access: FxHashMap<MemoryAccessFilter, ScriptHooks>,
    exit_hook: ScriptHooks,
    post_run: ScriptHooks,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct BasicBlockFilter {
    pc: Option<Address>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct InstructionFilter {
    pc: Option<Address>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct InterruptFilter {
    pc: Option<Address>,
    interrupt: Option<Interrupt>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct MemoryAccessFilter {
    memory_type: MemoryType,
    access_type: AccessType,
    pc: Option<MmioAddress>,
    address: Option<MmioAddress>,
}

type ScriptHooks = Vec<Function>;

macro_rules! source_module {
    ($path:literal) => {
        (
            concat!(env!("CARGO_MANIFEST_DIR"), "/hooks/modules/", $path),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/hooks/modules/",
                $path
            )),
        )
    };
}
const SOURCE_MODULES: [(&str, &str); 2] = [source_module!("dump.rn"), source_module!("trace.rn")];

impl HookRuntime {
    pub fn new(
        debug: bool,
        trace: bool,
        scripts: &[CustomHook],
        symbolizer: Arc<Mutex<Symbolizer>>,
    ) -> Result<Self> {
        // set up script engine context
        let mut context = rune::Context::with_default_modules()
            .context("Failed to create script engine context")?;

        // install rune modules
        context.install(&rune::modules::core::module()?)?;
        context.install(&rune::modules::fmt::module()?)?;
        context.install(&rune::modules::io::module(true)?)?;
        context.install(&rune::modules::macros::module()?)?;
        context.install(&rune::modules::test::module()?)?;

        // install hödur modules
        context.install(&common::module(symbolizer.clone())?)?;
        context.install(&symbolizer::module(symbolizer)?)?;
        context.install(&module_convert()?)?;
        context.install(&module_input()?)?;
        context.install(&module_log()?)?;
        context.install(&module_memory()?)?;
        context.install(&module_register()?)?;
        context.install(&module_system()?)?;
        context.install(&type_emulator()?)?;

        #[cfg(feature = "arm")]
        context.install(&arm::module()?)?;

        let runtime_context = Arc::new(context.runtime());

        // load scripts
        let scripts = scripts
            .iter()
            .map(|script| {
                let path = match script {
                    CustomHook::File(path) => path,
                    CustomHook::Script(path, _) => path,
                };
                let script = match script {
                    CustomHook::File(path) => fs::read_to_string(path)
                        .with_context(|| format!("Failed to read script {path:?}"))?,
                    CustomHook::Script(_, script) => script.clone(),
                };

                // load script
                let mut sources = Sources::new();
                let script = sources.insert(Source::with_path(
                    path.to_string_lossy(),
                    script,
                    Some(path),
                ));
                for (name, source) in SOURCE_MODULES {
                    sources.insert(Source::new(name, source));
                }

                // prepare script
                let mut diagnostics = Diagnostics::new();
                let result = rune::prepare(&mut sources)
                    .with_context(&context)
                    .with_diagnostics(&mut diagnostics)
                    .build()
                    .context("Failed to prepare script engine");

                // log script errors
                if !diagnostics.is_empty() {
                    // log warnings / errors are present
                    let (level, name) = if diagnostics.has_error() {
                        (log::Level::Error, "error")
                    } else {
                        (log::Level::Warn, "warning")
                    };
                    log::log!(
                        level,
                        "Script {:?} contain {}s, see stderr for details:",
                        path,
                        name
                    );

                    // write diagnostics to stderr
                    if log::log_enabled!(level) {
                        let mut writer = StandardStream::stderr(ColorChoice::Always);
                        diagnostics.emit(&mut writer, &sources)?;
                    }
                }

                // script unit
                let unit = result?;

                HookScript::new(runtime_context.clone(), unit, debug, trace, script, sources)
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self { scripts })
    }

    fn call_hooks<'a, F: Fn(&'a ScriptApi) -> I, I: Iterator<Item = &'a Function>>(
        &'a self,
        name: &str,
        f: F,
        args: Vec<Value>,
    ) -> Result<()> {
        for script in &self.scripts {
            if script
                .call_hooks(f(&script.api), args.clone())
                .with_context(|| format!("Call custom '{name}' hook"))?
            {
                return Ok(());
            }
        }

        Ok(())
    }

    pub fn on_init(&mut self) -> Result<()> {
        self.call_hooks("on_init", |api| api.init.iter(), vec![])
    }

    pub fn on_prepare_run(&self) -> Result<()> {
        debug_assert!(BUGS.lock().is_none());
        self.call_hooks("on_prepare_run", |api| api.prepare_run.iter(), vec![])
    }

    pub fn on_basic_block(&mut self, pc: Address) -> Result<()> {
        self.call_hooks(
            "on_basic_block",
            |api| {
                [
                    BasicBlockFilter { pc: Some(pc) },
                    BasicBlockFilter { pc: None },
                ]
                .into_iter()
                .filter_map(|filter| api.basic_block.get(&filter).map(|funcs| funcs.iter()))
                .flatten()
            },
            vec![Value::Integer(pc as i64)],
        )
    }

    pub fn on_instruction(&mut self, pc: Address) -> Result<()> {
        self.call_hooks(
            "on_instruction",
            |api| {
                [
                    InstructionFilter { pc: Some(pc) },
                    InstructionFilter { pc: None },
                ]
                .into_iter()
                .filter_map(|filter| api.instruction.get(&filter).map(|funcs| funcs.iter()))
                .flatten()
            },
            vec![Value::Integer(pc as i64)],
        )
    }

    pub fn on_interrupt(&self, pc: Address, interrupt: Interrupt) -> Result<()> {
        self.call_hooks(
            "on_interrupt",
            |api| {
                [
                    InterruptFilter {
                        pc: Some(pc),
                        interrupt: None,
                    },
                    InterruptFilter {
                        pc: Some(pc),
                        interrupt: Some(interrupt),
                    },
                    InterruptFilter {
                        pc: None,
                        interrupt: None,
                    },
                    InterruptFilter {
                        pc: None,
                        interrupt: Some(interrupt),
                    },
                ]
                .into_iter()
                .filter_map(|filter| api.interrupt.get(&filter).map(|funcs| funcs.iter()))
                .flatten()
            },
            vec![
                Value::Integer(pc as i64),
                Value::Integer(interrupt.num() as i64),
            ],
        )
    }

    pub fn on_memory_access(
        &self,
        memory_type: MemoryType,
        access_type: AccessType,
        pc: Address,
        address: Address,
        value: USize,
        size: u8,
    ) -> Result<()> {
        let args = vec![
            Value::Integer(pc as i64),
            Value::Integer(address as i64),
            Value::Integer(size as i64),
            Value::Integer(value as i64),
        ];

        for script in &self.scripts {
            let functions = [
                MemoryAccessFilter {
                    memory_type,
                    access_type,
                    pc: Some(pc),
                    address: None,
                },
                MemoryAccessFilter {
                    memory_type,
                    access_type,
                    pc: Some(pc),
                    address: Some(aligned(address)),
                },
                MemoryAccessFilter {
                    memory_type,
                    access_type,
                    pc: None,
                    address: None,
                },
                MemoryAccessFilter {
                    memory_type,
                    access_type,
                    pc: None,
                    address: Some(aligned(address)),
                },
            ]
            .into_iter()
            .filter_map(|filter| {
                script
                    .api
                    .memory_access
                    .get(&filter)
                    .map(|funcs| funcs.iter())
            })
            .flatten();

            if script
                .call_hooks(functions, args.clone())
                .context("Call custom 'on_memory_access' hook")?
            {
                return Ok(());
            }
        }

        Ok(())
    }

    pub fn on_exit_hook(&self, pc: Address) -> Result<()> {
        self.call_hooks(
            "on_exit_hook",
            |api| api.exit_hook.iter(),
            vec![Value::Integer(pc as i64)],
        )
    }

    pub fn on_post_run(&self) -> Result<()> {
        self.call_hooks("on_post_run", |api| api.post_run.iter(), vec![])
    }
}

impl HookScript {
    pub fn new(
        context: Arc<RuntimeContext>,
        unit: Unit,
        debug: bool,
        trace: bool,
        script: SourceId,
        sources: Sources,
    ) -> Result<Self> {
        // get main fn, script source path
        let fn_main = rune::Hash::type_hash(["main"]);
        let has_main = unit.iter_functions().any(|(func, _)| func == fn_main);

        // init VM
        let mut api = ScriptApi::default();

        // call script main or warn when missing
        if has_main {
            let mut vm = Vm::new(context, Arc::new(unit));
            let success = process_call_result(vm.call(fn_main, (&mut api,)), script, &sources)
                .with_context(|| {
                    format!(
                        "Call 'main' of script {:?} failed",
                        script_path(script, &sources)
                    )
                })?;

            if !success {
                anyhow::bail!(
                    "Call of 'main' in script {:?} returned error",
                    script_path(script, &sources)
                )
            }

            // warn when debug hooks are present in non-debug run
            if !(debug
                || api.prepare_run.is_empty()
                    && api.post_run.is_empty()
                    && api.exit_hook.is_empty()
                    && api.basic_block.is_empty()
                    && api.interrupt.is_empty()
                    && api.memory_access.is_empty())
            {
                log::warn!(
                    "Script {:?} added debug hooks while not in debug-mode, these hooks will not be executed",
                    script_path(script, &sources)
                );
            }

            // warn when basic block hooks are present in non-trace run
            if !trace && !api.basic_block.is_empty() {
                log::warn!(
                    "Script {:?} added basic block hooks while not in trace-mode, these hooks will not be executed",
                    script_path(script, &sources)
                );
            }

            // warn when instruction hooks are present in non-trace run
            if !trace && !api.instruction.is_empty() {
                log::warn!(
                    "Script {:?} added instruction hooks while not in trace-mode, these hooks will not be executed",
                    script_path(script, &sources)
                );
            }
        } else {
            // warn when useless script is added
            log::error!(
                "Script {:?} has no (pub) main function, this script will not be executed",
                script_path(script, &sources)
            );
        }

        Ok(Self {
            api,
            script,
            sources,
        })
    }

    fn call_hooks<'a>(
        &self,
        functions: impl Iterator<Item = &'a Function>,
        args: Vec<Value>,
    ) -> Result<bool> {
        for func in functions {
            log::trace!(
                "Calling hook function {} in script {:?}",
                func.type_hash(),
                script_path(self.script, &self.sources)
            );

            process_call_result(func.call(args.clone()), self.script, &self.sources)?;
        }

        Ok(false)
    }
}

fn script_path(script: SourceId, sources: &Sources) -> &str {
    sources
        .get(script)
        .map(|source| source.name())
        .unwrap_or("<unknown>")
}

fn process_call_result(
    result: Result<Value, VmError>,
    script: SourceId,
    sources: &Sources,
) -> Result<bool> {
    result
        .or_else(|err| {
            let mut writer = StandardStream::stderr(ColorChoice::Always);

            log::error!(
                "Failed to call custom hook function in script {:?}, see stderr for details:",
                script_path(script, sources)
            );
            err.emit(&mut writer, sources)
                .context("Failed to emit script errors to stderr")
                .and(
                    Err(err)
                        .context("Failed to call custom hook function (see stderr for details)"),
                )
        })
        .and_then(|value| match &value {
            Value::Unit => Ok(true),
            Value::Result(result)
                if result
                    .borrow_ref()
                    .map(|result| result.is_err())
                    .unwrap_or(false) =>
            {
                let result = result
                    .borrow_ref()
                    .context("Failed to borrow return value as Result")?;

                if let Err(value) = result.as_ref() {
                    match value {
                        Value::Any(any) => {
                            if let Ok(error) = any.downcast_borrow_ref::<anyhow::Error>() {
                                // pretty print anyhow error
                                log::error!("{}", *error);
                            } else {
                                // fallback to default impl (error type)
                                log::error!("{:?}", any);
                            }
                        }
                        value => {
                            log::error!("{:?}", value);
                        }
                    }

                    log::error!(
                        "in custom hook function in script {:?}",
                        script_path(script, sources)
                    );
                } else {
                    // checked in value match if condition
                    unreachable!();
                }

                Ok(false)
            }
            _ => {
                log::warn!(
                    "Custom hook function in script {:?} returned unexpected value {:#?}",
                    script_path(script, sources),
                    value
                );
                Ok(true)
            }
        })
}

fn module_system() -> Result<Module> {
    let mut module = Module::with_crate("system");

    // system control
    module.function(&["stop_fuzzer"], stop_fuzzer)?;
    module.function(&["stop_emulator"], stop_emulator)?;
    module.function(&["abort_emulator"], abort_emulator)?;

    Ok(module)
}

fn module_log() -> Result<Module> {
    let mut module = Module::with_crate("log");

    // log function
    module.function(&["trace"], |msg: &str| log::trace!("{}", msg))?;
    module.function(&["debug"], |msg: &str| log::debug!("{}", msg))?;
    module.function(&["info"], |msg: &str| log::info!("{}", msg))?;
    module.function(&["warn"], |msg: &str| log::warn!("{}", msg))?;
    module.function(&["error"], |msg: &str| log::error!("{}", msg))?;

    // log macro with format str
    module.macro_(&["trace"], |ctx, stream| {
        log_macro(ctx, stream, |msg| quote!(log::error(#msg)))
    })?;
    module.macro_(&["debug"], |ctx, stream| {
        log_macro(ctx, stream, |msg| quote!(log::debug(#msg)))
    })?;
    module.macro_(&["info"], |ctx, stream| {
        log_macro(ctx, stream, |msg| quote!(log::info(#msg)))
    })?;
    module.macro_(&["warn"], |ctx, stream| {
        log_macro(ctx, stream, |msg| quote!(log::warn(#msg)))
    })?;
    module.macro_(&["error"], |ctx, stream| {
        log_macro(ctx, stream, |msg| quote!(log::error(#msg)))
    })?;

    Ok(module)
}

fn log_macro<F: FnOnce(Quote<'_>) -> Quote<'_>>(
    ctx: &mut MacroContext<'_>,
    stream: &TokenStream,
    f: F,
) -> rune::Result<TokenStream> {
    let mut p = Parser::from_token_stream(stream, ctx.stream_span());
    let args = p.parse_all::<FormatArgs>()?;
    let expanded = args.expand(ctx)?;
    Ok(f(expanded).into_token_stream(ctx))
}

fn module_input() -> Result<Module> {
    let mut module = Module::with_crate("input");

    // system control
    module.function(&["add_bug"], input_add_bug)?;

    Ok(module)
}

fn module_memory() -> Result<Module> {
    let mut module = Module::with_crate("memory");

    // memory read
    module.function(&["read_u8"], |address| {
        memory_read::<u8, 1>(address).map(|byte| byte as u32)
    })?;
    module.function(&["read_u16"], memory_read::<u16, 2>)?;
    module.function(&["read_u32"], memory_read::<u32, 4>)?;
    module.function(&["read_u64"], memory_read::<u64, 8>)?;
    module.function(&["read_cstring"], memory_read_cstring)?;

    // memory write
    module.function(&["write_u8"], |address, value: u32| {
        memory_write::<u8, 1>(
            address,
            value
                .try_into()
                .with_context(|| format!("Value {value:#x?} too large for u8"))?,
        )
    })?;
    module.function(&["write_u16"], memory_write::<u16, 2>)?;
    module.function(&["write_u32"], memory_write::<u32, 4>)?;
    module.function(&["write_u64"], memory_write::<u64, 8>)?;

    Ok(module)
}

fn module_register() -> Result<Module> {
    let mut module = Module::with_crate("register");

    // register access
    module.function(&["list"], register_list)?;
    module.function(&["read"], register_read)?;
    module.function(&["write"], register_write)?;

    Ok(module)
}

// TODO: remove legacy convert
fn module_convert() -> Result<Module> {
    let mut module = Module::with_crate("convert");

    // convert to unsigned
    module.function(&["u8"], |val: usize| val as u8)?;
    module.function(&["u64"], |val: u8| val as u64)?;

    Ok(module)
}

fn type_emulator() -> Result<Module> {
    let mut module = Module::new();

    module.ty::<ScriptApi>()?;
    module.inst_fn("on_init", ScriptApi::on_init)?;
    module.inst_fn("on_prepare_run", ScriptApi::on_prepare_run)?;
    module.inst_fn("on_basic_block", ScriptApi::on_basic_block)?;
    module.inst_fn("on_instruction", ScriptApi::on_instruction)?;
    module.inst_fn("on_interrupt", ScriptApi::on_interrupt)?;
    module.inst_fn("on_mmio_read", ScriptApi::on_mmio_read)?;
    module.inst_fn("on_mmio_write", ScriptApi::on_mmio_write)?;
    module.inst_fn("on_ram_read", ScriptApi::on_ram_read)?;
    module.inst_fn("on_ram_write", ScriptApi::on_ram_write)?;
    module.inst_fn("on_rom_read", ScriptApi::on_rom_read)?;
    module.inst_fn("on_rom_write", ScriptApi::on_rom_write)?;
    module.inst_fn("on_exit_hook", ScriptApi::on_exit_hook)?;
    module.inst_fn("on_post_run", ScriptApi::on_post_run)?;

    Ok(module)
}

impl ScriptApi {
    /**
     * @Article Hook API
     * ## Initialization Hook
     * `api.on_init(function: Function)`
     *
     * Register `function` as initialization hook.
     * The hook will be executed after the initialization of the emulator/fuzzer.
     * This hook can be used to patch the firmware.
     *
     * Note: This hook is available in non-debug runs.
     *
     * Example:
     * ```rhai
     * pub fn main(api) {
     *     api.on_init(on_init);
     *     api.on_init(|| log::info!("Init!"));
     * }
     * fn on_init() {
     *     common::patch(0x400914, arm::RETURN);
     * }
     * ```
     */
    fn on_init(&mut self, function: Function) {
        log::debug!("api.on_init({})", function.type_hash());
        self.init.push(function);
    }

    /**
     * @Article Hook API
     * ## Prepare Run Hook
     * `api.on_prepare_run(function: Function)`
     *
     * Register `function` as a prepare run hook.
     * The hook will be executed before an input is run.
     *
     * Example:
     * ```rhai
     * pub fn main(api) {
     *     api.on_prepare_run(on_prepare_run);
     *     api.on_prepare_run(|| log::info!("Next Input"));
     * }
     * fn on_prepare_run() {
     *     log::info!("Next Input");
     * }
     * ```
     */
    fn on_prepare_run(&mut self, function: Function) {
        log::debug!("api.on_prepare_run({})", function.type_hash());
        self.prepare_run.push(function);
    }

    /**
     * @Article Hook API
     * ## Basic Block Hook
     * `api.on_basic_block(pc: Option<Address>, function: Function)`
     *
     * Register `function` as basic block hook, optionally with at `pc` filter.
     * The hook will be executed at the start of all or the specified basic block.
     *
     * Example:
     * ```rhai
     * pub fn main(api) {
     *     api.on_basic_block(None, on_basic_block);
     *     api.on_basic_block(Some(0x1040), |pc| log::info!("Hit 'on_bb_main' at {:08x}", pc));
     * }
     * fn on_basic_block(pc) {
     *     log::info!("Hit basic block at {:08x}", pc);
     * }
     * ```
     */
    fn on_basic_block(&mut self, pc: Option<Address>, function: Function) {
        log::debug!("api.on_basic_block({:x?}, {})", pc, function.type_hash());
        self.basic_block
            .entry(BasicBlockFilter { pc })
            .or_default()
            .push(function);
    }

    /**
     * @Article Hook API
     * ## Instruction Hook
     * `api.on_instruction(pc: Option<Address>, function: Function)`
     *
     * Register `function` as instruction hook, optionally with at `pc` filter.
     * The hook will be executed at the start of all or the specified instruction.
     *
     * Example:
     * ```rhai
     * pub fn main(api) {
     *     api.on_instruction(None, on_instruction);
     *     api.on_instruction(Some(0x1040), |pc| log::info!("Hit specific instruction at {:08x}", pc));
     * }
     * fn on_instruction(pc) {
     *     log::info!("Hit instruction at {:08x}", pc);
     * }
     * ```
     */
    fn on_instruction(&mut self, pc: Option<Address>, function: Function) {
        log::debug!("api.on_instruction({:x?}, {})", pc, function.type_hash());
        self.instruction
            .entry(InstructionFilter { pc })
            .or_default()
            .push(function);
    }

    /**
     * @Article Hook API
     * ## Interrupt Hook
     * `api.on_interrupt(pc: Option<Address>, interrupt: Option<i32>, function: Function)`
     *
     * Register `function` as interrupt hook, optionally with at `pc` and `interrupt` filter.
     * The hook will be executed when a specified interrupt occurs.
     *
     * Example:
     * ```rhai
     * pub fn main(api) {
     *     api.on_interrupt(None, None, on_interrupt);
     *     api.on_interrupt(None, Some(5), |pc, interrupt| log::info!("Interrupt {} raised at {:08x}", interrupt, pc));
     * }
     * fn on_interrupt(pc, interrupt) {
     *     log::info!("Interrupt {} raised at {:08x}", interrupt, pc);
     * }
     * ```
     */
    fn on_interrupt(&mut self, pc: Option<Address>, interrupt: Option<i32>, function: Function) {
        log::debug!(
            "api.on_interrupt({:x?}, {:x?}, {})",
            pc,
            interrupt,
            function.type_hash()
        );
        self.interrupt
            .entry(InterruptFilter {
                pc,
                interrupt: interrupt.map(Interrupt::from),
            })
            .or_default()
            .push(function);
    }

    /**
     * @Article Hook API
     * ## Register MMIO Hook
     * `api.on_mmio_read(pc: Option<Address>, address: Option<Address>, function: Function)`
     * `api.on_mmio_write(pc: Option<Address>, address: Option<Address>, function: Function)`
     *
     * Register `function` as a MMIO read or write hook, optionally with at `pc` and `address` filter.
     * The hook will be executed when a specified MMIO access occurs.
     *
     * Example:
     * ```rhai
     * pub fn main(api) {
     *     api.on_mmio_read(None, None, on_mmio_read);
     *     api.on_mmio_write(Some(0x40000), Some(0x80000000), |pc, address, size, data| log::info!("MMIO write to {:08x} with value {:08x}", address, value);
     * }
     * fn on_mmio_read(pc, address, size, data) {
     *     log::info!("MMIO READ from {:08x} at {:08x} with size {}, data = {:08x}", address, pc, size, data);
     * }
     * ```
     */
    fn on_mmio_read(&mut self, pc: Option<Address>, address: Option<Address>, function: Function) {
        log::debug!(
            "api.on_mmio_read({:x?}, {:x?}, {})",
            pc,
            address,
            function.type_hash()
        );
        self.memory_access
            .entry(MemoryAccessFilter {
                memory_type: MemoryType::Mmio,
                access_type: AccessType::Read,
                pc,
                address: address.map(aligned),
            })
            .or_default()
            .push(function);
    }
    fn on_mmio_write(&mut self, pc: Option<Address>, address: Option<Address>, function: Function) {
        log::debug!(
            "api.on_mmio_write({:x?}, {:x?}, {})",
            pc,
            address,
            function.type_hash()
        );
        self.memory_access
            .entry(MemoryAccessFilter {
                memory_type: MemoryType::Mmio,
                access_type: AccessType::Write,
                pc,
                address: address.map(aligned),
            })
            .or_default()
            .push(function);
    }

    /**
     * @Article Hook API
     * ## Register RAM Access Hook
     * `api.on_ram_read(pc: Option<Address>, address: Option<Address>, function: Function)`
     * `api.on_ram_write(pc: Option<Address>, address: Option<Address>, function: Function)`
     *
     * Register `function` as a RAM read or write hook, optionally with at `pc` and `address` filter.
     * The hook will be executed when a specified RAM access occurs.
     *
     * Example:
     * ```rhai
     * pub fn main(api) {
     *     api.on_ram_read(None, None, on_ram_read);
     *     api.on_ram_write(Some(0x40000), Some(0x80000000), |pc, address, size, data| log::info!("RAM write to {:08x} with value {:08x}", address, value);
     * }
     * fn on_ram_read(pc, address, size, data) {
     *     log::info!("RAM read from {:08x} at {:08x} with size {}, data = {:08x}", address, pc, size, data);
     * }
     * ```
     */
    fn on_ram_read(&mut self, pc: Option<Address>, address: Option<Address>, function: Function) {
        log::debug!(
            "api.on_ram_read({:x?}, {:x?}, {})",
            pc,
            address,
            function.type_hash()
        );
        self.memory_access
            .entry(MemoryAccessFilter {
                memory_type: MemoryType::Ram,
                access_type: AccessType::Read,
                pc,
                address: address.map(aligned),
            })
            .or_default()
            .push(function);
    }
    fn on_ram_write(&mut self, pc: Option<Address>, address: Option<Address>, function: Function) {
        log::debug!(
            "api.on_ram_write({:x?}, {:x?}, {})",
            pc,
            address,
            function.type_hash()
        );
        self.memory_access
            .entry(MemoryAccessFilter {
                memory_type: MemoryType::Ram,
                access_type: AccessType::Write,
                pc,
                address: address.map(aligned),
            })
            .or_default()
            .push(function);
    }

    /**
     * @Article Hook API
     * ## Register ROM Access Hook
     * `api.on_rom_read(pc: Option<Address>, address: Option<Address>, function: Function)`
     * `api.on_rom_write(pc: Option<Address>, address: Option<Address>, function: Function)`
     *
     * Register `function` as a ROM read or write hook, optionally with at `pc` and `address` filter.
     * The hook will be executed when a specified ROM access occurs.
     *
     * Example:
     * ```rhai
     * pub fn main(api) {
     *     api.on_rom_read(None, None, on_rom_read);
     *     api.on_rom_write(Some(0x40000), Some(0x80000000), |pc, address, size, data| log::info!("ROM write to {:08x} with value {:08x}", address, value);
     * }
     * fn on_rom_read(pc, address, size, data) {
     *     log::info!("ROM read from {:08x} at {:08x} with size {}, data = {:08x}", address, pc, size, data);
     * }
     * ```
     */
    fn on_rom_read(&mut self, pc: Option<Address>, address: Option<Address>, function: Function) {
        log::debug!(
            "api.on_rom_read({:x?}, {:x?}, {})",
            pc,
            address,
            function.type_hash()
        );
        self.memory_access
            .entry(MemoryAccessFilter {
                memory_type: MemoryType::Rom,
                access_type: AccessType::Read,
                pc,
                address: address.map(aligned),
            })
            .or_default()
            .push(function);
    }
    fn on_rom_write(&mut self, pc: Option<Address>, address: Option<Address>, function: Function) {
        log::debug!(
            "api.on_rom_write({:x?}, {:x?}, {})",
            pc,
            address,
            function.type_hash()
        );
        self.memory_access
            .entry(MemoryAccessFilter {
                memory_type: MemoryType::Rom,
                access_type: AccessType::Write,
                pc,
                address: address.map(aligned),
            })
            .or_default()
            .push(function);
    }

    /**
     * @Article Hook API
     * ## Exit Block Hook
     * `api.on_exit_hook(function: Function)`
     *
     * Register `function` as a exit block hook.
     * The hook will be executed when a configured target exit hook was reached.
     *
     * Example:
     * ```rhai
     * pub fn main(api) {
     *     api.on_exit_hook(on_exit_hook);
     *     api.on_exit_hook(|pc| log::info!("Hit exit hook at {:08x}", pc));
     * }
     * fn on_exit_hook(pc) {
     *     log::info!("Hit exit hook at {:08x}", pc);
     * }
     * ```
     */
    fn on_exit_hook(&mut self, function: Function) {
        log::debug!("api.on_exit_hook({})", function.type_hash());
        self.exit_hook.push(function);
    }

    /**
     * @Article Hook API
     * ## Post Run Hook
     * `api.on_post_run(function: Function)`
     *
     * Register `function` as a post run hook.
     * The hook will be executed after an input was run.
     *
     * Example:
     * ```rhai
     * pub fn main(api) {
     *     api.on_post_run(on_post_run);
     *     api.on_post_run(|| log::info!("Input End"));
     * }
     * fn on_post_run() {
     *     log::info!("Input End");
     * }
     * ```
     */
    fn on_post_run(&mut self, function: Function) {
        log::debug!("api.on_post_run({})", function.type_hash());
        self.post_run.push(function);
    }
}

/**
 * @Article Script Functions
 * ## Stop fuzzer
 * `system::stop_fuzzer()`
 *
 * Stops the fuzzer after this execution (no new input will be executed).
 * Does not stop the current execution.
 *
 * Example:
 * ```rhai
 * system::stop_fuzzer();
 * ```
 */
fn stop_fuzzer() {
    log::debug!("stop_fuzzer called");
    EXIT.store(true, Ordering::SeqCst)
}

/**
 * @Article Script Functions
 * ## Stop emulator
 * `system::stop_emulator()`
 *
 * Stops the emulator after this basic block.
 * Does not stop the fuzzer (new inputs will be executed after this one).
 *
 * Example:
 * ```rhai
 * system::stop_emulator();
 * ```
 */
fn stop_emulator() {
    log::debug!("stop_emulator called");
    STOP.store(true, Ordering::SeqCst)
}

/**
 * @Article Script Functions
 * ## Abort emulator
 * `system::abort_emulator()`
 *
 * Aborts the emulator, this will terminate the emulator as soon as possible.
 *
 * Example:
 * ```rhai
 * system::abort_emulator();
 * ```
 */
fn abort_emulator() {
    log::warn!("abort_emulator called");
    TERM.store(true, Ordering::SeqCst)
}

/**
 * @Article Script Functions
 * ## Add bug to input
 * `input::add_bug(bug: String)`
 *
 * Add `bug` to the list of bugs hit by this input.
 * Example:
 * ```rhai
 * input::add_bug("CVE-EXAMPLE-123");
 * ```
 */
fn input_add_bug(bug: String) {
    log::debug!("add_bug {:?} called", bug);

    let mut guard = BUGS.lock();
    let bugs = guard.get_or_insert_with(Default::default);

    if !bugs.contains(&bug) {
        bugs.push(bug);
    } else {
        log::debug!("input already contains bug {:?}", bug);
    }
}

/**
 * @Article Script Functions
 * ## List registers
 * `register::list() -> Vec<String>`
 *
 * Example:
 * ```rhai
 * for name in register::list() {
 *     log::info!("{} = {:08x}", name, register::read(name)?);
 * }
 * ```
 */
fn register_list() -> Vec<String> {
    Register::printable()
        .iter()
        .map(ToString::to_string)
        .collect()
}

/**
 * @Article Script Functions
 * ## Read register
 * `register::read(name: &str) -> Result<USize>`
 *
 * Example:
 * ```rhai
 * log::info!("R0 = {:08x}", register::read("R0")?);
 * ```
 */
fn register_read(name: &str) -> Result<USize> {
    Register::try_from(name).map(|reg| qcontrol().register(reg))
}

/**
 * @Article Script Functions
 * ## Write register
 * `register::write(name: &str, value: USize) -> Result<()>`
 *
 * Example:
 * ```rhai
 * register::write("R0", 0xDEADBEEF)?;
 * ```
 */
fn register_write(name: &str, value: USize) -> Result<()> {
    Register::try_from(name).map(|reg| qcontrol_mut().set_register(reg, value))
}

/**
 * @Article Script Functions
 * ## Read memory
 * `read_u*(addr: USize) -> Result<u*>`
 * `memory::{read_u8, read_u16, read_u32, read_u64}`
 *
 * Example:
 * ```rhai
 * let addr = 0xDEADBEEF;
 * let value = memory::read_u32(addr)?;
 * log::info!("*{:08x} = {:08x}", addr, value);
 * ```
 */
fn memory_read<T: Primitive<Buf = [u8; N]> + Default + Debug, const N: usize>(
    address: Address,
) -> Result<T> {
    let result = qcontrol().read::<T, N>(address);
    match &result {
        Ok(value) => {
            log::trace!("read({:#x?}) -> {:#x?}", address, value);
        }
        Err(err) => {
            log::warn!("read({:#x?}) failed: {:?}", address, err);
        }
    }

    result
}

/**
 * @Article Script Functions
 * ## Write memory
 * `memory::write_u*(addr: USize, value: u*) -> Result<()>`
 * `memory::{write_u8, write_u16, write_u32, write_u64}`
 *
 * Example:
 * ```rhai
 * let addr = 0xDEADBEEF;
 * let value = memory::write_u8(addr, 0x42)?;
 * let value = memory::write_u16(addr, 0x1020)?;
 * ```
 */
fn memory_write<T: Primitive<Buf = [u8; N]> + Debug, const N: usize>(
    address: Address,
    value: T,
) -> Result<()> {
    let result = qcontrol_mut().write::<T, N>(address, value);
    match &result {
        Ok(()) => {
            log::trace!("write({:#x?}, {:#x?})", address, value);
        }
        Err(err) => {
            log::warn!("write({:#x?}, {:#x?}) failed: {:?}", address, value, err);
        }
    };

    result
}

/**
 * @Article Script Functions
 * ## Read c string
 * `memory::read_cstring(addr: USize) -> Result<String>`
 *
 * Example:
 * ```rhai
 * let addr = 0xDEADBEEF;
 * let value = read_cstring(addr)?;
 * log::info!("*{:08x} = '{}'", addr, value);
 * ```
 */
fn memory_read_cstring(address: Address) -> Result<String> {
    let cstring = qcontrol()
        .read_cstr(address)
        .map(CStr::to_string_lossy)
        .map(|cow| cow.to_string())
        .map(String::from);
    log::trace!("read_cstring({:#x?}) -> {:#x?}", address, cstring);

    cstring
}
