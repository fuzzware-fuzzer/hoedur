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

use std::{fmt, io};

use qemu_rs::ISize;

use crate::hooks::debug::printf_compat::argument::DoubleFormat;

use super::argument::{Argument, Flags, Specifier};

struct DummyWriter(usize);

impl fmt::Write for DummyWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0 += s.len();
        Ok(())
    }
}

struct WriteCounter<'a, T: fmt::Write>(&'a mut T, usize);

impl<'a, T: fmt::Write> fmt::Write for WriteCounter<'a, T> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.1 += s.len();
        self.0.write_str(s)
    }
}

struct FmtWriter<T: io::Write>(T, io::Result<()>);

impl<T: io::Write> fmt::Write for FmtWriter<T> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        match self.0.write_all(s.as_bytes()) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.1 = Err(e);
                Err(fmt::Error)
            }
        }
    }
}

struct IoWriteCounter<'a, T: io::Write>(&'a mut T, usize);

impl<'a, T: io::Write> io::Write for IoWriteCounter<'a, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write_all(buf)?;
        self.1 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

fn write_str(
    w: &mut impl fmt::Write,
    flags: Flags,
    width: ISize,
    precision: Option<ISize>,
    string: &str,
) -> fmt::Result {
    let precision = precision.unwrap_or(string.len() as ISize);
    if flags.contains(Flags::LEFT_ALIGN) {
        write!(
            w,
            "{:1$.prec$}",
            string,
            width as usize,
            prec = precision as usize
        )
    } else {
        write!(
            w,
            "{:>1$.prec$}",
            string,
            width as usize,
            prec = precision as usize
        )
    }
}

macro_rules! define_numeric {
    ($w: expr, $data: expr, $flags: expr, $width: expr, $precision: expr) => {
        define_numeric!($w, $data, $flags, $width, $precision, "")
    };
    ($w: expr, $data: expr, $flags: expr, $width: expr, $precision: expr, $ty:expr) => {{
        use fmt::Write;
        if $flags.contains(Flags::LEFT_ALIGN) {
            if $flags.contains(Flags::PREPEND_PLUS) {
                write!(
                    $w,
                    concat!("{:<+width$.prec$", $ty, "}"),
                    $data,
                    width = $width as usize,
                    prec = $precision as usize
                )
            } else if $flags.contains(Flags::PREPEND_SPACE) && !$data.is_sign_negative() {
                write!(
                    $w,
                    concat!(" {:<width$.prec$", $ty, "}"),
                    $data,
                    width = ($width as usize).wrapping_sub(1),
                    prec = $precision as usize
                )
            } else {
                write!(
                    $w,
                    concat!("{:<width$.prec$", $ty, "}"),
                    $data,
                    width = $width as usize,
                    prec = $precision as usize
                )
            }
        } else if $flags.contains(Flags::PREPEND_PLUS) {
            if $flags.contains(Flags::PREPEND_ZERO) {
                write!(
                    $w,
                    concat!("{:+0width$.prec$", $ty, "}"),
                    $data,
                    width = $width as usize,
                    prec = $precision as usize
                )
            } else {
                write!(
                    $w,
                    concat!("{:+width$.prec$", $ty, "}"),
                    $data,
                    width = $width as usize,
                    prec = $precision as usize
                )
            }
        } else if $flags.contains(Flags::PREPEND_ZERO) {
            if $flags.contains(Flags::PREPEND_SPACE) && !$data.is_sign_negative() {
                let mut d = DummyWriter(0);
                let _ = write!(
                    d,
                    concat!("{:.prec$", $ty, "}"),
                    $data,
                    prec = $precision as usize
                );
                if d.0 + 1 > $width as usize {
                    $width += 1;
                }
                write!(
                    $w,
                    concat!(" {:0width$.prec$", $ty, "}"),
                    $data,
                    width = ($width as usize).wrapping_sub(1),
                    prec = $precision as usize
                )
            } else {
                write!(
                    $w,
                    concat!("{:0width$.prec$", $ty, "}"),
                    $data,
                    width = $width as usize,
                    prec = $precision as usize
                )
            }
        } else {
            if $flags.contains(Flags::PREPEND_SPACE) && !$data.is_sign_negative() {
                let mut d = DummyWriter(0);
                let _ = write!(
                    d,
                    concat!("{:.prec$", $ty, "}"),
                    $data,
                    prec = $precision as usize
                );
                if d.0 + 1 > $width as usize {
                    $width = d.0 as i32 + 1;
                }
            }
            write!(
                $w,
                concat!("{:width$.prec$", $ty, "}"),
                $data,
                width = $width as usize,
                prec = $precision as usize
            )
        }
    }};
}

macro_rules! define_unumeric {
    ($w: expr, $data: expr, $flags: expr, $width: expr, $precision: expr) => {
        define_unumeric!($w, $data, $flags, $width, $precision, "")
    };
    ($w: expr, $data: expr, $flags: expr, $width: expr, $precision: expr, $ty:expr) => {{
        if $flags.contains(Flags::LEFT_ALIGN) {
            if $flags.contains(Flags::ALTERNATE_FORM) {
                write!(
                    $w,
                    concat!("{:<#width$", $ty, "}"),
                    $data,
                    width = $width as usize
                )
            } else {
                write!(
                    $w,
                    concat!("{:<width$", $ty, "}"),
                    $data,
                    width = $width as usize
                )
            }
        } else if $flags.contains(Flags::ALTERNATE_FORM) {
            if $flags.contains(Flags::PREPEND_ZERO) {
                write!(
                    $w,
                    concat!("{:#0width$", $ty, "}"),
                    $data,
                    width = $width as usize
                )
            } else {
                write!(
                    $w,
                    concat!("{:#width$", $ty, "}"),
                    $data,
                    width = $width as usize
                )
            }
        } else if $flags.contains(Flags::PREPEND_ZERO) {
            write!(
                $w,
                concat!("{:0width$", $ty, "}"),
                $data,
                width = $width as usize
            )
        } else {
            write!(
                $w,
                concat!("{:width$", $ty, "}"),
                $data,
                width = $width as usize
            )
        }
    }};
}

/// Write to a struct that implements [`fmt::Write`].
///
/// # Differences
///
/// There are a few differences from standard printf format:
///
/// - only valid UTF-8 data can be printed.
/// - an `X` format specifier with a `#` flag prints the hex data in uppercase,
///   but the leading `0x` is still lowercase
/// - an `o` format specifier with a `#` flag precedes the number with an `o`
///   instead of `0`
/// - `g`/`G` (shorted floating point) is aliased to `f`/`F`` (decimal floating
///   point)
/// - same for `a`/`A` (hex floating point)
/// - the `n` format specifier, [`Specifier::WriteBytesWritten`], is not
///   implemented and will cause an error if encountered.
pub fn fmt_write(w: &mut impl fmt::Write) -> impl FnMut(Argument) -> ISize + '_ {
    use fmt::Write;
    move |Argument {
              flags,
              mut width,
              precision,
              specifier,
          }| {
        let mut w = WriteCounter(w, 0);
        let w = &mut w;
        let res = match specifier {
            Specifier::Percent => w.write_char('%'),
            Specifier::Bytes(data) => write_str(w, flags, width, precision, data),
            Specifier::Hex(data) => {
                define_unumeric!(w, data, flags, width, precision.unwrap_or(0), "x")
            }
            Specifier::UpperHex(data) => {
                define_unumeric!(w, data, flags, width, precision.unwrap_or(0), "X")
            }
            Specifier::Octal(data) => {
                define_unumeric!(w, data, flags, width, precision.unwrap_or(0), "o")
            }
            Specifier::Uint(data) => {
                define_unumeric!(w, data, flags, width, precision.unwrap_or(0))
            }
            Specifier::Int(data) => define_numeric!(w, data, flags, width, precision.unwrap_or(0)),
            Specifier::Double { value, format } => match format {
                DoubleFormat::Normal
                | DoubleFormat::UpperNormal
                | DoubleFormat::Auto
                | DoubleFormat::UpperAuto
                | DoubleFormat::Hex
                | DoubleFormat::UpperHex => {
                    define_numeric!(w, value, flags, width, precision.unwrap_or(6))
                }
                DoubleFormat::Scientific => {
                    define_numeric!(w, value, flags, width, precision.unwrap_or(6), "e")
                }
                DoubleFormat::UpperScientific => {
                    define_numeric!(w, value, flags, width, precision.unwrap_or(6), "E")
                }
            },
            Specifier::Char(data) => {
                if flags.contains(Flags::LEFT_ALIGN) {
                    write!(w, "{:width$}", data as char, width = width as usize)
                } else {
                    write!(w, "{:>width$}", data as char, width = width as usize)
                }
            }
            Specifier::String(data) | Specifier::Pointer(data) => {
                if flags.contains(Flags::LEFT_ALIGN) {
                    write!(w, "{:<width$p}", data as *const u8, width = width as usize)
                } else if flags.contains(Flags::PREPEND_ZERO) {
                    write!(w, "{:0width$p}", data as *const u8, width = width as usize)
                } else {
                    write!(w, "{:width$p}", data as *const u8, width = width as usize)
                }
            }
            Specifier::WriteBytesWritten(_, _) => Err(Default::default()),
        };
        match res {
            Ok(_) => w.1 as ISize,
            Err(_) => -1,
        }
    }
}
