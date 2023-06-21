#![macro_use]

use crate::TCGHelperInfo;

pub const TCG_CALL_DEFAULT: u32 = 0;

pub trait TcgCallback {
    fn register(&self);
    fn as_callback(&self) -> *mut TCGHelperInfo;
}

impl TcgCallback for TCGHelperInfo {
    fn register(&self) {
        unsafe { crate::add_tcg_function(self.as_callback()) }
    }

    fn as_callback(&self) -> *mut TCGHelperInfo {
        self as *const _ as *mut _
    }
}

pub fn no_callback() -> *mut TCGHelperInfo {
    std::ptr::null_mut()
}

#[macro_export]
macro_rules! qemu_callflag {
    (i32) => {
        $crate::dh_callflag_i32
    };
    (u32) => {
        $crate::dh_callflag_i32
    };
    (i64) => {
        $crate::dh_callflag_i64
    };
    (u64) => {
        $crate::dh_callflag_i64
    };
    (*mut $type:ty) => {
        $crate::dh_callflag_ptr
    };
    (*const $type:ty) => {
        $crate::dh_callflag_ptr
    };
    ($type:ty) => {{
        let _ = (std::ptr::null_mut() as $type);
        $crate::dh_callflag_ptr
    }};
    (()) => {
        $crate::dh_callflag_void
    };
    (!) => {
        $crate::dh_callflag_noreturn
    };
}

#[macro_export]
macro_rules! qemu_typecode {
    (i32) => {
        $crate::dh_typecode_s32
    };
    (u32) => {
        $crate::dh_typecode_i32
    };
    (i64) => {
        $crate::dh_typecode_s64
    };
    (u64) => {
        $crate::dh_typecode_i64
    };
    (*mut $type:ty) => {
        $crate::dh_typecode_ptr
    };
    (*const $type:ty) => {
        $crate::dh_typecode_ptr
    };
    ($type:ty) => {{
        let _ = (std::ptr::null_mut() as $type);
        $crate::dh_typecode_ptr
    }};
    (()) => {
        $crate::dh_typecode_void
    };
    (!) => {
        $crate::dh_typecode_noreturn
    };
}

#[macro_export]
macro_rules! dh_typemask {
    ($t:ident, $n:expr) => {
        $crate::qemu_typecode!($t) << ($n * 3)
    };
}

#[macro_export]
macro_rules! tcg_function {
    // external Rust-like functions
    { $flags:expr; $vis:vis fn $func:ident($($arg:ident: $type:ident),*) $body:block } => {
        tcg_function!{ $vis fn $func($($arg: $type),*) -> () $body; $flags | $crate::dh_callflag_void; 0; [$($arg: $type),*]; 0 }
    };
    { $flags:expr; $vis:vis fn $func:ident($($arg:ident: $type:ident),*) -> ! $body:block } => {
        tcg_function!{ $vis fn $func($($arg: $type),*) -> () $body; $flags | $crate::dh_callflag_noreturn; 0; [$($arg: $type),*]; 0 }
    };
    { $flags:expr; $vis:vis fn $func:ident($($arg:ident: $type:ident),*) -> $ret:ident $body:block } => {
        tcg_function!{ $vis fn $func($($arg: $type),*) -> $ret $body; $flags | qemu_callflag!($ret); 0; [$($arg: $type),*]; 0 }
    };

    // internal QEMU argument typemask expansion
    { $vis:vis fn $func:ident($($arg:ident: $type:ty),*) -> $ret:ty $body:block; $flags:expr; $typemask:expr; [$next_arg:ident: $next_type:ident, $($args:ident: $types:ident),*]; $n:expr } => {
        tcg_function!{ $vis fn $func($($arg: $type),*) -> $ret $body; $flags; $typemask | $crate::dh_typemask!($next_type, $n); [$($args: $types),*]; $n + 1 }
    };
    { $vis:vis fn $func:ident($($arg:ident: $type:ty),*) -> $ret:ty $body:block; $flags:expr; $typemask:expr; [$next_arg:ident: $next_type:ident]; $n:expr } => {
        tcg_function!{ $vis fn $func($($arg: $type),*) -> $ret $body; $flags; $typemask | $crate::dh_typemask!($next_type, $n) }
    };
    { $vis:vis fn $func:ident($($arg:ident: $type:ty),*) -> $ret:ty $body:block; $flags:expr; $typemask:expr } => {
        $vis extern "C" fn $func( $($arg: $type),* ) -> $ret $body

        $crate::paste::paste!{
            $vis const [<$func:upper _INFO>]: $crate::TCGHelperInfo = $crate::TCGHelperInfo {
                func: $func as *mut  std::ffi::c_void,
                name: $crate::cstr!($func),
                flags: $flags,
                typemask: $typemask,
            };
        }
    };
}
