use std::convert::TryFrom;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum Register {
    // General-purpose registers
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,

    // PC register
    R15,

    // Special-purpose program status registers (Cortex-M)
    xPSR,

    // Current Program Status register
    CPSR,

    // Saved Program Status Registers
    SPSR,
}

#[allow(non_upper_case_globals)]
impl Register {
    /// Stack Pointer
    pub const SP: Register = Self::R13;

    /// Link Register
    pub const LR: Register = Self::R14;

    /// Program Counter
    pub const PC: Register = Self::R15;
}

#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
enum RegisterIndex {
    R(usize),
    xPSR,
    CPSR,
    SPSR,
}

impl Register {
    pub fn printable() -> [Self; 18] {
        use Register::*;

        [
            R0,
            R1,
            R2,
            R3,
            R4,
            R5,
            R6,
            R7,
            R8,
            R9,
            R10,
            R11,
            R12,
            Register::SP,
            Register::LR,
            Register::PC,
            Register::xPSR,
            Register::CPSR,
        ]
    }

    fn register_index(self) -> RegisterIndex {
        match self {
            // General-purpose registers
            Self::R0 => RegisterIndex::R(0),
            Self::R1 => RegisterIndex::R(1),
            Self::R2 => RegisterIndex::R(2),
            Self::R3 => RegisterIndex::R(3),
            Self::R4 => RegisterIndex::R(4),
            Self::R5 => RegisterIndex::R(5),
            Self::R6 => RegisterIndex::R(6),
            Self::R7 => RegisterIndex::R(7),
            Self::R8 => RegisterIndex::R(8),
            Self::R9 => RegisterIndex::R(9),
            Self::R10 => RegisterIndex::R(10),
            Self::R11 => RegisterIndex::R(11),
            Self::R12 => RegisterIndex::R(12),
            Self::R13 => RegisterIndex::R(13),
            Self::R14 => RegisterIndex::R(14),

            // PC register
            Self::R15 => RegisterIndex::R(15),

            // Special-purpose program status registers (Cortex-M)
            Self::xPSR => RegisterIndex::xPSR,

            // Current Program Status register
            Self::CPSR => RegisterIndex::CPSR,

            // Saved Program Status Registers
            Self::SPSR => RegisterIndex::SPSR,
        }
    }
}

impl std::fmt::Display for Register {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                // General-purpose registers
                Self::R0 => "R0",
                Self::R1 => "R1",
                Self::R2 => "R2",
                Self::R3 => "R3",
                Self::R4 => "R4",
                Self::R5 => "R5",
                Self::R6 => "R6",
                Self::R7 => "R7",
                Self::R8 => "R8",
                Self::R9 => "R9",
                Self::R10 => "R10",
                Self::R11 => "R11",
                Self::R12 => "R12",
                Self::SP => "SP",
                Self::LR => "LR",

                // PC register
                Self::PC => "PC",

                // Special-purpose program status registers (Cortex-M)
                Self::xPSR => "xPSR",

                // Current Program Status register
                Self::CPSR => "CPSR",

                // Saved Program Status Registers
                Self::SPSR => "SPSR",
            }
        )
    }
}

impl TryFrom<&str> for Register {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        // NOTE: we explicitly want "xPSR"
        #[allow(clippy::match_str_case_mismatch)]
        Ok(match s.to_uppercase().as_str() {
            // General-purpose registers
            "R0" => Self::R0,
            "R1" => Self::R1,
            "R2" => Self::R2,
            "R3" => Self::R3,
            "R4" => Self::R4,
            "R5" => Self::R5,
            "R6" => Self::R6,
            "R7" => Self::R7,
            "R8" => Self::R8,
            "R9" => Self::R9,
            "R10" => Self::R10,
            "R11" => Self::R11,
            "R12" => Self::R12,
            "R13" => Self::R13,
            "R14" => Self::R14,

            // General-purpose registers aliases (R13-14)
            "SP" => Self::SP,
            "LR" => Self::LR,

            // PC register
            "R15" => Self::R15,
            "PC" => Self::PC,

            // Special-purpose program status registers (Cortex-M)
            "xPSR" => Self::xPSR,
            "XPSR" => Self::xPSR,

            // Current Program Status register
            "CPSR" => Self::CPSR,

            // Saved Program Status Registers
            "SPSR" => Self::SPSR,

            register => anyhow::bail!("unknown register {:?}", register),
        })
    }
}

impl crate::RegisterAccess for qemu_sys::CPUARMState {
    fn read(&self, register: Register) -> crate::Address {
        match register.register_index() {
            RegisterIndex::R(idx) => self.regs[idx],
            RegisterIndex::xPSR => qemu_sys::xpsr_read(self),
            RegisterIndex::CPSR => unsafe { qemu_sys::cpsr_read(self as *const _ as *mut _) },
            RegisterIndex::SPSR => unimplemented!(),
        }
    }

    fn write(&mut self, register: Register, value: crate::Address) {
        match register.register_index() {
            RegisterIndex::R(idx) => self.regs[idx] = value,
            RegisterIndex::xPSR => unimplemented!(),
            RegisterIndex::CPSR => unimplemented!(),
            RegisterIndex::SPSR => unimplemented!(),
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    User = 0b10000,
    FIQ = 0b10001,
    IRQ = 0b10010,
    Supervisor = 0b10011,
    Monitor = 0b10110,
    Abort = 0b10111,
    Hypvisor = 0b11010,
    Undefined = 0b11011,
    System = 0b11111,
}

impl Mode {
    pub const MODE_MASK: crate::Address = 0b1_1111;

    pub fn from_cpsr(cpsr: crate::Address) -> Result<Mode, crate::Address> {
        Self::from_u32(cpsr & Self::MODE_MASK)
    }

    pub fn from_u32(mode: crate::Address) -> Result<Mode, crate::Address> {
        Ok(match mode {
            0b10000 => Self::User,
            0b10001 => Self::FIQ,
            0b10010 => Self::IRQ,
            0b10011 => Self::Supervisor,
            0b10110 => Self::Monitor,
            0b10111 => Self::Abort,
            0b11010 => Self::Hypvisor,
            0b11011 => Self::Undefined,
            0b11111 => Self::System,
            mode => return Err(mode),
        })
    }
}
