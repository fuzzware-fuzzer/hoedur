/* Copyright (c) 2018 Ben Schattinger <developer@lights0123.com>

Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without
limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice
shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE. */

use anyhow::Result;
use itertools::Itertools;
use qemu_rs::ISize;

use super::super::PrintfArguments;
use super::argument::{Argument, DoubleFormat, Flags, SignedInt, Specifier, UnsignedInt};

fn next_char(sub: &str) -> &str {
    sub.get(1..).unwrap_or("")
}

/// Parse the [Flags field](https://en.wikipedia.org/wiki/Printf_format_string#Flags_field).
fn parse_flags(mut sub: &str) -> (Flags, &str) {
    let mut flags: Flags = Flags::empty();
    while let Some(ch) = sub.chars().next() {
        flags.insert(match ch {
            '-' => Flags::LEFT_ALIGN,
            '+' => Flags::PREPEND_PLUS,
            ' ' => Flags::PREPEND_SPACE,
            '0' => Flags::PREPEND_ZERO,
            '\'' => Flags::THOUSANDS_GROUPING,
            '#' => Flags::ALTERNATE_FORM,
            _ => break,
        });
        sub = next_char(sub)
    }
    (flags, sub)
}

/// Parse the [Width field](https://en.wikipedia.org/wiki/Printf_format_string#Width_field).
fn parse_width<'a>(mut sub: &'a str, args: &mut PrintfArguments) -> Result<(ISize, &'a str)> {
    let mut width = 0;
    if sub.starts_with('*') {
        return Ok((args.arg()?, next_char(sub)));
    }
    while let Some(ch) = sub.chars().next() {
        match ch {
            // https://rust-malaysia.github.io/code/2020/07/11/faster-integer-parsing.html#the-bytes-solution
            '0'..='9' => width = width * 10 + (ch as u8 & 0x0f) as ISize,
            _ => break,
        }
        sub = next_char(sub);
    }
    Ok((width, sub))
}

/// Parse the [Precision field](https://en.wikipedia.org/wiki/Printf_format_string#Precision_field).
fn parse_precision<'a>(
    sub: &'a str,
    args: &mut PrintfArguments,
) -> Result<(Option<ISize>, &'a str)> {
    Ok(match sub.chars().next() {
        Some('.') => {
            let (prec, sub) = parse_width(next_char(sub), args)?;
            (Some(prec), sub)
        }
        _ => (None, sub),
    })
}

#[derive(Debug, Copy, Clone)]
enum Length {
    Int,
    /// `hh`
    Char,
    /// `h`
    Short,
    /// `l`
    Long,
    /// `ll`
    LongLong,
    /// `z`
    Usize,
    /// `t`
    Isize,
}

impl Length {
    fn parse_signed(self, args: &mut PrintfArguments) -> Result<SignedInt> {
        Ok(match self {
            Length::Int => SignedInt::Int(args.arg()?),
            Length::Char => SignedInt::Char(args.arg()?),
            Length::Short => SignedInt::Short(args.arg()?),
            Length::Long => SignedInt::Long(args.arg()?),
            Length::LongLong => SignedInt::LongLong(args.arg()?),
            // for some reason, these exist as different options, yet produce the same output
            Length::Usize | Length::Isize => SignedInt::Isize(args.arg()?),
        })
    }
    fn parse_unsigned(self, args: &mut PrintfArguments) -> Result<UnsignedInt> {
        Ok(match self {
            Length::Int => UnsignedInt::Int(args.arg()?),
            Length::Char => UnsignedInt::Char(args.arg()?),
            Length::Short => UnsignedInt::Short(args.arg()?),
            Length::Long => UnsignedInt::Long(args.arg()?),
            Length::LongLong => UnsignedInt::LongLong(args.arg()?),
            // for some reason, these exist as different options, yet produce the same output
            Length::Usize | Length::Isize => UnsignedInt::Isize(args.arg()?),
        })
    }
}

/// Parse the [Length field](https://en.wikipedia.org/wiki/Printf_format_string#Length_field).
fn parse_length(sub: &str) -> (Length, &str) {
    match sub.chars().next() {
        Some('h') => match sub.chars().nth(1) {
            Some('h') => (Length::Char, sub.get(2..).unwrap_or("")),
            _ => (Length::Short, next_char(sub)),
        },
        Some('l') => match sub.chars().nth(1) {
            Some('l') => (Length::LongLong, sub.get(2..).unwrap_or("")),
            _ => (Length::Long, next_char(sub)),
        },
        Some('z') => (Length::Usize, next_char(sub)),
        Some('t') => (Length::Isize, next_char(sub)),
        _ => (Length::Int, sub),
    }
}

/// Parse a format parameter and write it somewhere.
pub fn format(
    format: &str,
    mut args: PrintfArguments,
    mut handler: impl FnMut(Argument) -> ISize,
) -> Result<ISize> {
    let mut iter = format.split('%');
    let mut written = 0;

    macro_rules! err {
        ($ex: expr) => {{
            let res = $ex;
            if res < 0 {
                return Ok(-1);
            } else {
                written += res;
            }
        }};
    }
    if let Some(begin) = iter.next() {
        err!(handler(Specifier::Bytes(begin).into()));
    }
    let mut last_was_percent = false;
    for (sub, next) in iter.map(Some).chain(core::iter::once(None)).tuple_windows() {
        let sub = match sub {
            Some(sub) => sub,
            None => break,
        };
        if last_was_percent {
            err!(handler(Specifier::Bytes(sub).into()));
            last_was_percent = false;
            continue;
        }
        let (flags, sub) = parse_flags(sub);
        let (width, sub) = parse_width(sub, &mut args)?;
        let (precision, sub) = parse_precision(sub, &mut args)?;
        let (length, sub) = parse_length(sub);
        let ch = sub
            .chars()
            .next()
            .unwrap_or(if next.is_some() { '%' } else { '\0' });
        err!(handler(Argument {
            flags,
            width,
            precision,
            specifier: match ch {
                '%' => {
                    last_was_percent = true;
                    Specifier::Percent
                }
                'd' | 'i' => Specifier::Int(length.parse_signed(&mut args)?),
                'x' => Specifier::Hex(length.parse_unsigned(&mut args)?),
                'X' => Specifier::UpperHex(length.parse_unsigned(&mut args)?),
                'u' => Specifier::Uint(length.parse_unsigned(&mut args)?),
                'o' => Specifier::Octal(length.parse_unsigned(&mut args)?),
                'f' | 'F' => Specifier::Double {
                    value: args.arg()?,
                    format: DoubleFormat::Normal.set_upper(ch.is_ascii_uppercase()),
                },
                'e' | 'E' => Specifier::Double {
                    value: args.arg()?,
                    format: DoubleFormat::Scientific.set_upper(ch.is_ascii_uppercase()),
                },
                'g' | 'G' => Specifier::Double {
                    value: args.arg()?,
                    format: DoubleFormat::Auto.set_upper(ch.is_ascii_uppercase()),
                },
                'a' | 'A' => Specifier::Double {
                    value: args.arg()?,
                    format: DoubleFormat::Hex.set_upper(ch.is_ascii_uppercase()),
                },
                's' => Specifier::String(args.arg()?),
                'c' => Specifier::Char(args.arg()?),
                'p' => Specifier::Pointer(args.arg()?),
                'n' => Specifier::WriteBytesWritten(written, args.arg()?),
                _ => return Ok(-1),
            },
        }));
        err!(handler(Specifier::Bytes(next_char(sub)).into()));
    }

    Ok(written)
}
