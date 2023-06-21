use std::{
    fmt,
    hash::{Hash, Hasher},
};

use crate::NvicException;
use serde::{Deserialize, Serialize};

#[repr(transparent)]
#[derive(Default, Clone, Copy, Eq, Serialize, Deserialize)]
pub struct Exception(i32);

impl Hash for Exception {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.num().hash(state);
    }
}

impl PartialEq for Exception {
    fn eq(&self, other: &Self) -> bool {
        self.num() == other.num()
    }
}

impl From<i32> for Exception {
    fn from(val: i32) -> Self {
        Self(val)
    }
}

impl fmt::Debug for Exception {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for Exception {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(exception) = self.as_cpu() {
            write!(f, "{exception}")
        } else if let Some(exception) = self.as_nvic() {
            write!(f, "{exception}")
        } else {
            write!(f, "{} (unknown)", self.num())
        }
    }
}

impl Exception {
    pub fn num(self) -> i32 {
        self.0.abs()
    }

    pub(crate) fn raw_num(self) -> i32 {
        self.0
    }

    pub fn is_valid(self) -> bool {
        self.as_cpu().is_some() || self.as_nvic().is_some()
    }

    pub fn is_fatal(self) -> bool {
        self.as_cpu()
            .map(CpuException::is_fatal)
            .or_else(|| self.as_nvic().map(NvicException::is_fatal))
            .unwrap_or(false)
    }

    pub fn as_cpu(self) -> Option<CpuException> {
        CpuException::from_exception(self)
    }

    pub fn as_nvic(self) -> Option<NvicException> {
        NvicException::from_exception(self)
    }

    pub fn name(self) -> &'static str {
        self.as_cpu()
            .map(CpuException::name)
            .or_else(|| self.as_nvic().map(NvicException::name))
            .unwrap_or("invalid")
    }
}

#[repr(i32)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CpuException {
    Reset = 0,
    UdefinedInstruction = 1,
    SoftwareInterrupt = 2,
    PrefetchAbort = 3,
    DataAbort = 4,
    IRQ = 5,
    FIQ = 6,
    Breakpoint = 7,
    /// Return from v7M exception.
    ExceptionExit = 8,
    KernelTrap = 9,
    HyperVisorCall = 11,
    HyperVisorTrap = 12,
    SecureMonitorCall = 13,
    VIRQ = 14,
    VFIQ = 15,
    SemihostingCall = 16,
    /// v7M NOCP UsageFault
    NOCP = 17,
    /// v7M INVSTATE UsageFault
    INVSTATE = 18,
    /// v8M STKOF UsageFault
    STKOF = 19,
    /// v7M fault during lazy FP stacking
    LAZYFP = 20,
    /// v8M LSERR SecureFault
    LSERR = 21,
    /// v7M UNALIGNED UsageFault
    UNALIGNED = 22,
    /// v7M DIVBYZERO UsageFault
    DIVBYZERO = 23,
    VSERR = 24,
}

impl From<CpuException> for Exception {
    fn from(exec: CpuException) -> Self {
        Exception::from(exec.num())
    }
}

impl CpuException {
    pub fn num(self) -> i32 {
        self as i32
    }

    pub fn from_exception(exception: Exception) -> Option<CpuException> {
        Some(match exception.raw_num() {
            1 => Self::UdefinedInstruction,
            2 => Self::SoftwareInterrupt,
            3 => Self::PrefetchAbort,
            4 => Self::DataAbort,
            5 => Self::IRQ,
            6 => Self::FIQ,
            7 => Self::Breakpoint,
            8 => Self::ExceptionExit,
            9 => Self::KernelTrap,
            11 => Self::HyperVisorCall,
            12 => Self::HyperVisorTrap,
            13 => Self::SecureMonitorCall,
            14 => Self::VIRQ,
            15 => Self::VFIQ,
            16 => Self::SemihostingCall,
            17 => Self::NOCP,
            18 => Self::INVSTATE,
            19 => Self::STKOF,
            20 => Self::LAZYFP,
            21 => Self::LSERR,
            22 => Self::UNALIGNED,
            23 => Self::DIVBYZERO,
            24 => Self::VSERR,
            _ => return None,
        })
    }

    pub fn is_fatal(self) -> bool {
        matches!(
            self,
            Self::UdefinedInstruction | Self::PrefetchAbort | Self::DataAbort
        )
    }

    pub fn available_interrupts(_force_raise: bool) -> [Exception; 2] {
        [Self::IRQ.into(), Self::FIQ.into()]
    }

    pub fn name(self) -> &'static str {
        match self.num() {
            1 => "UDEF",
            2 => "SWI",
            3 => "PREFETCH_ABORT",
            4 => "DATA_ABORT",
            5 => "IRQ",
            6 => "FIQ",
            7 => "BKPT",
            8 => "EXCEPTION_EXIT",
            9 => "KERNEL_TRAP",
            11 => "HVC",
            12 => "HYP_TRAP",
            13 => "SMC",
            14 => "VIRQ",
            15 => "VFIQ",
            16 => "SEMIHOST",
            17 => "NOCP",
            18 => "INVSTATE",
            19 => "STKOF",
            20 => "LAZYFP",
            21 => "LSERR",
            22 => "UNALIGNED",
            23 => "DIVBYZERO",
            24 => "VSERR",

            _ => "invalid",
        }
    }
}

impl fmt::Debug for CpuException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for CpuException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.num(), self.name())
    }
}

impl CpuException {
    pub(crate) fn pend(self) {
        // ARM specific stuff
        let cpu = crate::qcontrol::cpu_mut();
        cpu.env.exception.syndrome = 0;
        cpu.env.exception.target_el = 1;

        // pend generic exception
        let exception: Exception = self.into();
        exception.pend();
    }
}
