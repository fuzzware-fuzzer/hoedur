#[allow(unconditional_panic)]
const fn illegal_null_in_string() {
    [][0]
}

#[doc(hidden)]
pub const fn validate_cstr_contents(bytes: &[u8]) {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\0' {
            illegal_null_in_string();
        }
        i += 1;
    }
}

#[macro_export]
macro_rules! cstr {
    ( $s:literal ) => {{
        $crate::cstr::validate_cstr_contents($s.as_bytes());
        concat!($s, "\0").as_ptr() as *const i8
    }};
    ( $name:ident ) => {{
        concat!(std::stringify!($name), "\0").as_ptr() as *const i8
    }};
    ( $qconst:path ) => {{
        $qconst as *const u8 as *const i8
    }};
    ( $s:expr ) => {{
        $s.as_ptr() as *const i8
    }};
}
