pub use paste;

pub mod cstr;
pub mod mem;
pub mod tcg;

#[allow(clippy::missing_safety_doc)]
#[allow(clippy::redundant_static_lifetimes)]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::upper_case_acronyms)]
#[allow(deref_nullptr)]
#[allow(improper_ctypes)] // NOTE: bindgen generates tests to verify struct alignment, this should be safe
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub(crate) mod bindings;

pub use bindings::workaround::*;

#[cfg(feature = "arm")]
pub use bindings::arm::*;

#[cfg(feature = "arm")]
pub const PAGE_SIZE: usize = 0x400;

#[cfg(feature = "arm")]
pub fn arm_feature(env: &CPUARMState, feature: arm_features) -> bool {
    (env.features & 1u64.rotate_left(feature.0)) != 0
}

#[cfg(feature = "arm")]
pub fn xpsr_read(env: &CPUARMState) -> u32 {
    (env.NF & 0x80000000)
        | if env.ZF == 0 { 1 << 30 } else { 0 }
        | (env.CF << 29)
        | ((env.VF & 0x80000000) >> 3)
        | (env.QF << 27)
        | if env.thumb { 1 << 24 } else { 0 }
        | ((env.condexec_bits & 3) << 25)
        | ((env.condexec_bits & 0xfc) << 8)
        | (env.GE << 16)
        | env.v7m.exception as u32
}
