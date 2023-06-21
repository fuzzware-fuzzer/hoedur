use std::{error, fmt, io, result, string};

/// A type alias for `Result<T, triage::Error>`.
pub type Result<T> = result::Result<T, Error>;

/// An error that can occur during analysis of a trace.
#[derive(Debug)]
pub struct Error {
    inner: ErrorKind,
}

impl Error {
    pub fn new(k: ErrorKind) -> Self {
        Error { inner: k }
    }

    /// Return the kind of this Error.
    pub fn kind(&self) -> &ErrorKind {
        &self.inner
    }

    /// Unwrap this error into its underlying kind.
    pub fn into_kind(self) -> ErrorKind {
        self.inner
    }
}

/// The specifc type of Error that can during analysis of a trace.
#[derive(Debug)]
pub enum ErrorKind {
    /// An I/O error that occured while analyzing a trace.
    Io(io::Error),
    /// Display format error
    Fmt(fmt::Error),
    /// Unable to convert bytes (standard input) to UTF-8
    Utf8(string::FromUtf8Error),
    /// Symbolizer Error
    Symbolizer(symbolizer::Error),
    /// Bincode Error
    Bincode(bincode::ErrorKind),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error {
            inner: ErrorKind::Io(e),
        }
    }
}

impl From<fmt::Error> for Error {
    fn from(e: fmt::Error) -> Error {
        Error {
            inner: ErrorKind::Fmt(e),
        }
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(e: string::FromUtf8Error) -> Error {
        Error {
            inner: ErrorKind::Utf8(e),
        }
    }
}

impl From<symbolizer::Error> for Error {
    fn from(e: symbolizer::Error) -> Error {
        Error {
            inner: ErrorKind::Symbolizer(e),
        }
    }
}

impl From<bincode::ErrorKind> for Error {
    fn from(e: bincode::ErrorKind) -> Error {
        Error {
            inner: ErrorKind::Bincode(e),
        }
    }
}

impl From<Box<bincode::ErrorKind>> for Error {
    fn from(e: Box<bincode::ErrorKind>) -> Error {
        Self::from(*e)
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match self.inner {
            ErrorKind::Io(ref e) => Some(e),
            ErrorKind::Fmt(ref e) => Some(e),
            ErrorKind::Utf8(ref e) => Some(e),
            ErrorKind::Symbolizer(ref e) => Some(e),
            ErrorKind::Bincode(ref e) => Some(e),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.inner {
            ErrorKind::Io(ref e) => e.fmt(f),
            ErrorKind::Fmt(ref e) => e.fmt(f),
            ErrorKind::Utf8(ref e) => e.fmt(f),
            ErrorKind::Symbolizer(ref e) => e.fmt(f),
            ErrorKind::Bincode(ref e) => e.fmt(f),
        }
    }
}
