use std::convert::TryFrom;

pub mod board;
pub mod exception;
pub mod exception_level;
pub mod nvic;
pub mod register;
pub mod snapshot;
pub mod systick;

pub use exception::{CpuException, Exception};
pub use nvic::{InternalException, NvicException};
pub use register::Register;
pub use systick::systick;

#[derive(Debug, Clone, Copy)]
pub enum Event {
    ExceptionLevelChange,
    SysTickGetTicks,
    SysTickChanged,
}

#[derive(Debug, Clone, Copy)]
pub enum CpuModel {
    Arm1026,
    Arm1136,
    Arm1136R2,
    Arm1176,
    Arm11mpcore,
    Arm926,
    Arm946,
    CortexA15,
    CortexA7,
    CortexA8,
    CortexA9,
    CortexM0,
    CortexM3,
    CortexM33,
    CortexM4,
    CortexM55,
    CortexM7,
    CortexR5,
    CortexR5f,
    Pxa250,
    Pxa255,
    Pxa260,
    Pxa261,
    Pxa262,
    Pxa270A0,
    Pxa270A1,
    Pxa270,
    Pxa270B0,
    Pxa270B1,
    Pxa270C0,
    Pxa270C5,
    Sa1100,
    Sa1110,
    Ti925t,
}

impl Default for CpuModel {
    fn default() -> Self {
        Self::CortexM4
    }
}

impl CpuModel {
    pub fn has_nvic(&self) -> bool {
        matches!(
            self,
            Self::CortexM0
                | Self::CortexM3
                | Self::CortexM33
                | Self::CortexM4
                | Self::CortexM55
                | Self::CortexM7
        )
    }

    pub fn as_cstr(&self) -> *const i8 {
        use qemu_sys::cstr;
        match self {
            Self::Arm1026 => cstr!("arm1026-arm-cpu"),
            Self::Arm1136 => cstr!("arm1136-arm-cpu"),
            Self::Arm1136R2 => cstr!("arm1136-r2-arm-cpu"),
            Self::Arm1176 => cstr!("arm1176-arm-cpu"),
            Self::Arm11mpcore => cstr!("arm11mpcore-arm-cpu"),
            Self::Arm926 => cstr!("arm926-arm-cpu"),
            Self::Arm946 => cstr!("arm946-arm-cpu"),
            Self::CortexA15 => cstr!("cortex-a15-arm-cpu"),
            Self::CortexA7 => cstr!("cortex-a7-arm-cpu"),
            Self::CortexA8 => cstr!("cortex-a8-arm-cpu"),
            Self::CortexA9 => cstr!("cortex-a9-arm-cpu"),
            Self::CortexM0 => cstr!("cortex-m0-arm-cpu"),
            Self::CortexM3 => cstr!("cortex-m3-arm-cpu"),
            Self::CortexM33 => cstr!("cortex-m33-arm-cpu"),
            Self::CortexM4 => cstr!("cortex-m4-arm-cpu"),
            Self::CortexM55 => cstr!("cortex-m55-arm-cpu"),
            Self::CortexM7 => cstr!("cortex-m7-arm-cpu"),
            Self::CortexR5 => cstr!("cortex-r5-arm-cpu"),
            Self::CortexR5f => cstr!("cortex-r5f-arm-cpu"),
            Self::Pxa250 => cstr!("pxa250-arm-cpu"),
            Self::Pxa255 => cstr!("pxa255-arm-cpu"),
            Self::Pxa260 => cstr!("pxa260-arm-cpu"),
            Self::Pxa261 => cstr!("pxa261-arm-cpu"),
            Self::Pxa262 => cstr!("pxa262-arm-cpu"),
            Self::Pxa270A0 => cstr!("pxa270-a0-arm-cpu"),
            Self::Pxa270A1 => cstr!("pxa270-a1-arm-cpu"),
            Self::Pxa270 => cstr!("pxa270-arm-cpu"),
            Self::Pxa270B0 => cstr!("pxa270-b0-arm-cpu"),
            Self::Pxa270B1 => cstr!("pxa270-b1-arm-cpu"),
            Self::Pxa270C0 => cstr!("pxa270-c0-arm-cpu"),
            Self::Pxa270C5 => cstr!("pxa270-c5-arm-cpu"),
            Self::Sa1100 => cstr!("sa1100-arm-cpu"),
            Self::Sa1110 => cstr!("sa1110-arm-cpu"),
            Self::Ti925t => cstr!("ti925t-arm-cpu"),
        }
    }
}

impl AsRef<str> for CpuModel {
    fn as_ref(&self) -> &str {
        match self {
            Self::Arm1026 => "arm1026",
            Self::Arm1136 => "arm1136",
            Self::Arm1136R2 => "arm1136-r2",
            Self::Arm1176 => "arm1176",
            Self::Arm11mpcore => "arm11mpcore",
            Self::Arm926 => "arm926",
            Self::Arm946 => "arm946",
            Self::CortexA15 => "cortex-a15",
            Self::CortexA7 => "cortex-a7",
            Self::CortexA8 => "cortex-a8",
            Self::CortexA9 => "cortex-a9",
            Self::CortexM0 => "cortex-m0",
            Self::CortexM3 => "cortex-m3",
            Self::CortexM33 => "cortex-m33",
            Self::CortexM4 => "cortex-m4",
            Self::CortexM55 => "cortex-m55",
            Self::CortexM7 => "cortex-m7",
            Self::CortexR5 => "cortex-r5",
            Self::CortexR5f => "cortex-r5f",
            Self::Pxa250 => "pxa250",
            Self::Pxa255 => "pxa255",
            Self::Pxa260 => "pxa260",
            Self::Pxa261 => "pxa261",
            Self::Pxa262 => "pxa262",
            Self::Pxa270A0 => "pxa270-a0",
            Self::Pxa270A1 => "pxa270-a1",
            Self::Pxa270 => "pxa270",
            Self::Pxa270B0 => "pxa270-b0",
            Self::Pxa270B1 => "pxa270-b1",
            Self::Pxa270C0 => "pxa270-c0",
            Self::Pxa270C5 => "pxa270-c5",
            Self::Sa1100 => "sa1100",
            Self::Sa1110 => "sa1110",
            Self::Ti925t => "ti925t",
        }
    }
}

impl TryFrom<&str> for CpuModel {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(match value {
            "arm1026" => Self::Arm1026,
            "arm1136" => Self::Arm1136,
            "arm1136-r2" => Self::Arm1136R2,
            "arm1176" => Self::Arm1176,
            "arm11mpcore" => Self::Arm11mpcore,
            "arm926" => Self::Arm926,
            "arm946" => Self::Arm946,
            "cortex-a15" => Self::CortexA15,
            "cortex-a7" => Self::CortexA7,
            "cortex-a8" => Self::CortexA8,
            "cortex-a9" => Self::CortexA9,
            "cortex-m0" => Self::CortexM0,
            "cortex-m3" => Self::CortexM3,
            "cortex-m33" => Self::CortexM33,
            "cortex-m4" => Self::CortexM4,
            "cortex-m55" => Self::CortexM55,
            "cortex-m7" => Self::CortexM7,
            "cortex-r5" => Self::CortexR5,
            "cortex-r5f" => Self::CortexR5f,
            "pxa250" => Self::Pxa250,
            "pxa255" => Self::Pxa255,
            "pxa260" => Self::Pxa260,
            "pxa261" => Self::Pxa261,
            "pxa262" => Self::Pxa262,
            "pxa270-a0" => Self::Pxa270A0,
            "pxa270-a1" => Self::Pxa270A1,
            "pxa270" => Self::Pxa270,
            "pxa270-b0" => Self::Pxa270B0,
            "pxa270-b1" => Self::Pxa270B1,
            "pxa270-c0" => Self::Pxa270C0,
            "pxa270-c5" => Self::Pxa270C5,
            "sa1100" => Self::Sa1100,
            "sa1110" => Self::Sa1110,
            "ti925t" => Self::Ti925t,
            _ => anyhow::bail!("unknown cpu type"),
        })
    }
}
