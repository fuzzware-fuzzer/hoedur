use std::{borrow::Cow, ffi::CStr, fmt::Write, mem};

use anyhow::{Context, Result};
use endiannezz::Primitive;
use qemu_rs::{qcontrol, Address, Register, USize};
use serde::{Deserialize, Serialize};

use super::HookTarget;

mod printf_compat;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugHook {
    name: Option<String>,
    #[serde(rename = "type")]
    hook_type: DebugHookType,
    #[serde(default = "Default::default")]
    option: DebugHookOption,
    #[serde(flatten)]
    target: HookTarget,
}

impl DebugHook {
    pub fn new(
        name: Option<String>,
        hook_type: DebugHookType,
        option: DebugHookOption,
        target: HookTarget,
    ) -> Self {
        Self {
            name,
            hook_type,
            option,
            target,
        }
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref().or_else(|| self.target().name())
    }

    pub fn target(&self) -> &HookTarget {
        &self.target
    }

    pub fn execute(&self) -> Result<Option<String>> {
        self.hook_type.execute(&self.option)
    }

    pub fn is_deprecated(&self) -> bool {
        matches!(
            self.hook_type,
            DebugHookType::Putc2
                | DebugHookType::Putd2
                | DebugHookType::Puts2
                | DebugHookType::Fputs
                | DebugHookType::Fputs2
                | DebugHookType::Sprintf
                | DebugHookType::SprintfVaList
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DebugHookType {
    Putc,
    Putc2,
    Putd,
    Putd2,
    Puts,
    Puts2,
    Fputs,
    Fputs2,
    Printf,
    Sprintf,
    PrintfVaList,
    SprintfVaList,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DebugHookOption {
    skip: Option<usize>,
    newline: Option<bool>,
}

impl DebugHookType {
    pub fn execute(&self, option: &DebugHookOption) -> Result<Option<String>> {
        let skip = |default| option.skip.unwrap_or(default);
        let newline = option
            .newline
            .unwrap_or(matches!(self, Self::Puts | Self::Puts2));

        match self {
            Self::SprintfVaList => hook_printf(skip(1), true),
            Self::PrintfVaList => hook_printf(skip(0), true),
            Self::Sprintf => hook_printf(skip(1), false),
            Self::Printf => hook_printf(skip(0), false),
            Self::Fputs => hook_puts(skip(0)),
            Self::Fputs2 => hook_puts(skip(1)),
            Self::Puts => hook_puts(skip(0)),
            Self::Puts2 => hook_puts(skip(1)),
            Self::Putd => hook_putd(skip(0)),
            Self::Putd2 => hook_putd(skip(1)),
            Self::Putc => hook_putc(skip(0)),
            Self::Putc2 => hook_putc(skip(1)),
        }
        // optionally add newline
        .map(|option| {
            option.map(|string| {
                if newline {
                    format!("{string}\n")
                } else {
                    string
                }
            })
        })
    }
}

trait Arguments {
    fn next<T: Primitive<Buf = [u8; N]>, const N: usize>(&mut self) -> Result<T>;
}

pub struct CallArgs {
    register: Vec<USize>,
    stack: Address,
}

impl CallArgs {
    fn new() -> Result<Self> {
        Ok(Self {
            register: Self::registers()
                .iter()
                .map(|reg| qcontrol().register(*reg))
                .collect(),
            stack: Self::stack(),
        })
    }

    fn arg(n: usize) -> Result<USize> {
        let mut args = Self::new()?;

        // skip args
        for _ in 0..n {
            let _: Result<USize> = args.next();
        }

        args.next()
    }
}

impl Arguments for CallArgs {
    fn next<T: Primitive<Buf = [u8; N]>, const N: usize>(&mut self) -> Result<T> {
        // TODO: this is likely wonky
        if N <= mem::size_of::<USize>() && !self.register.is_empty() {
            // get next register bytes
            let bytes = self.register.remove(0).to_le_bytes();

            // move up to N least significat bytes
            let mut buffer = [0u8; N];
            buffer[..N].clone_from_slice(&bytes[..N]);

            // convert to target type
            Ok(T::from_le_bytes(buffer))
        } else {
            // align stack pointer
            self.stack += self.stack % N as u32;

            // read arg from memory
            let arg = qcontrol()
                .read(self.stack)
                .context("Failed to read va_list argument from memory")?;

            // move stack pointer to next arg
            self.stack += N as u32;

            Ok(arg)
        }
    }
}

#[cfg(feature = "arm")]
impl CallArgs {
    fn registers() -> [Register; 4] {
        [Register::R0, Register::R1, Register::R2, Register::R3]
    }

    fn stack() -> Address {
        qcontrol().register(Register::SP)
    }
}

pub struct VaList {
    pointer: Address,
}

impl VaList {
    fn new(va_list: Address) -> Self {
        log::debug!("VaList at {:#x?}", va_list);

        Self { pointer: va_list }
    }
}

impl Arguments for VaList {
    // TODO: test non-arm vargs
    fn next<T: Primitive<Buf = [u8; N]>, const N: usize>(&mut self) -> Result<T> {
        #[cfg(feature = "arm")]
        // at least word aligned
        let align = std::cmp::max(std::mem::size_of::<u16>(), N);
        #[cfg(not(feature = "arm"))]
        let align = N;

        // align pointer
        self.pointer += self.pointer % align as u32;

        // read arg from memory
        let arg = qcontrol()
            .read(self.pointer)
            .context("Failed to read va_list argument from memory")?;

        // move pointer to next arg
        self.pointer += N as u32;

        Ok(arg)
    }
}

pub enum PrintfArguments {
    CallArgs(CallArgs),
    VaList(VaList),
}

impl PrintfArguments {
    fn new(mut args: CallArgs, va_list: bool) -> Result<Self> {
        Ok(if va_list {
            Self::VaList(VaList::new(args.next()?))
        } else {
            Self::CallArgs(args)
        })
    }

    fn arg<T: Primitive<Buf = [u8; N]>, const N: usize>(&mut self) -> Result<T> {
        match self {
            Self::CallArgs(args) => args.next(),
            Self::VaList(va_list) => va_list.next(),
        }
    }
}

fn cstr<'a>(addr: u32) -> Result<Cow<'a, str>> {
    qcontrol()
        .read_cstr(addr)
        .map(CStr::to_string_lossy)
        .map_err(|err| {
            log::warn!("invalid string at {:#x?}: {:?}", addr, err);
            err
        })
}

fn log_printf(args: Vec<USize>, fmt: &str) {
    // skip when debug log is disabled
    if !log::log_enabled!(log::Level::Debug) {
        return;
    }

    // collect skipped arguments
    let mut log = String::new();
    for arg in args {
        let _ = write!(log, "{arg:#x?}, ");
    }

    log::debug!("printf({}{:?})", log, fmt);
}

fn hook_printf(skip: usize, va_list: bool) -> Result<Option<String>> {
    let mut args = CallArgs::new().context("get function call args")?;
    let skipped = (0..skip).map(|_| args.next()).collect::<Result<Vec<_>>>()?;

    let format = cstr(args.next()?).context("read format str")?;
    log::trace!("format = {:?}", format);
    log_printf(skipped, &format);

    let printf_args = PrintfArguments::new(args, va_list)?;
    let mut string = String::with_capacity(format.len() * 2);
    {
        let mut writer = printf_compat::writer::fmt_write(&mut string);
        printf_compat::parser::format(&format, printf_args, |arg| {
            log::trace!("arg = {:x?}", arg);

            // read string pointer from memory
            if let printf_compat::argument::Specifier::String(pointer) = arg.specifier {
                let result = cstr(pointer).context("read string pointer");
                match result {
                    Ok(data) => {
                        let mut arg = arg;
                        arg.specifier = printf_compat::argument::Specifier::Bytes(&data);
                        return writer(arg);
                    }
                    Err(e) => log::warn!("{:?}", e),
                }
            }

            writer(arg)
        })
        .context("parse printf format")?;
    }

    Ok(Some(string))
}

fn hook_puts(skip: usize) -> Result<Option<String>> {
    let arg = CallArgs::arg(skip)?;

    cstr(arg).map(|string| {
        log::debug!("puts({:?})", string);
        Some(string.into())
    })
}

fn hook_putd(skip: usize) -> Result<Option<String>> {
    CallArgs::arg(skip).map(|arg| {
        log::debug!("putd({:?})", arg);
        Some(format!("{arg}"))
    })
}

fn hook_putc(skip: usize) -> Result<Option<String>> {
    let arg = CallArgs::arg(skip)?;
    let c = char::from_u32(arg);

    log::debug!("putc({:?})", c);

    Ok(c.map(String::from))
}
