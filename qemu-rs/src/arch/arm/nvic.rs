use std::fmt;

use crate::{qcontrol, qcontrol_mut, Exception};

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NvicException(i32);

impl From<i32> for NvicException {
    fn from(val: i32) -> Self {
        Self(val)
    }
}

impl From<NvicException> for Exception {
    fn from(exec: NvicException) -> Self {
        Exception::from(-exec.num())
    }
}

impl NvicException {
    pub fn from_exception(exception: Exception) -> Option<Self> {
        let nvic_exception = Self(-exception.raw_num());

        nvic_exception.is_valid().then_some(nvic_exception)
    }

    pub fn num(self) -> i32 {
        self.0
    }

    pub fn is_none(self) -> bool {
        self.0 == 0
    }

    pub fn is_valid(self) -> bool {
        self.is_internal() || self.is_external()
    }

    pub fn is_fatal(self) -> bool {
        self.as_internal()
            .map(InternalException::is_fatal)
            .unwrap_or(false)
    }

    pub fn is_internal(self) -> bool {
        matches!(self.0, 1..=15)
    }

    pub fn is_external(self) -> bool {
        matches!(self.0, 16..=512)
    }

    pub fn as_internal(self) -> Option<InternalException> {
        InternalException::from_exception(self)
    }

    pub fn available_interrupts(force_raise: bool) -> Vec<Exception> {
        let nvic = qcontrol()
            .board()
            .expect("fuzz board state is available")
            .nvic()
            .expect("NVIC state is available");

        nvic.vectors
            .iter()
            .enumerate()
            .filter_map(|(num, irq)| {
                let exception = NvicException::from(num as i32);

                // enabled external interrupt
                if irq.enabled == 1 && exception.is_external() {
                    // will raise / preempt irq
                    let will_raise = irq.pending == 0
                        && irq.active == 0
                        && (irq.prio as i32) < nvic.exception_prio;

                    // filter forced irq raise
                    if !force_raise || will_raise {
                        return Some(exception.into());
                    }
                }

                None
            })
            .collect()
    }

    pub fn name(self) -> &'static str {
        match self.0 {
            // internal
            1 => "Reset",
            2 => "NMI",
            3 => "HardFault",
            4 => "MemoryManagement",
            5 => "BusFault",
            6 => "UsageFault",
            7 => "Reserved",
            8 => "Reserved",
            9 => "Reserved",
            10 => "Reserved",
            11 => "SVC",
            12 => "DebugMon",
            13 => "Reserved",
            14 => "PendSV",
            15 => "SysTick",

            // external
            16..=512 => "IRQn",

            _ => "invalid",
        }
    }
}

impl fmt::Debug for NvicException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for NvicException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.num(), self.name())
    }
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternalException {
    Reset = 1,
    NonMaskableInterrupt = 2,

    /// HardFault `HFSR`
    /// - Bus error on a vector read `VECTTBL`
    /// - Fault escalated to a hard fault `FORCED`
    HardFault = 3,

    /// MemManage `MMFAR`
    /// - MPU or default memory map mismatch:
    ///     - on instruction access `IACCVIOL`
    ///     - on data access `DACCVIOL`
    ///     - during exception stacking `MSTKERR`
    ///     - during exception unstacking `MUNSKERR`
    MemoryManagement = 4,

    /// BusFault `BFSR`
    /// - Bus error:
    ///     - during exception stacking `STKERR`
    ///     - during exception unstacking `UNSTKERR`
    ///     - during instruction prefetch `IBUSERR`
    /// - Precise data bus error `PRECISERR`
    /// - Imprecise data bus error `IMPRECISERR`
    BusFault = 5,

    /// UsageFault `UFSR`
    /// - Attempt to access a coprocessor `NOCP`
    /// - Undefined instruction `UNDEFINSTR`
    /// - Attempt to enter an invalid instruction set state `INVSTATE`
    /// - Invalid EXC_RETURN value `INVPC`
    /// - Illegal unaligned load or store `UNALIGNED`
    /// - Divide By 0 `DIVBYZERO`
    UsageFault = 6,

    Reserved7 = 7,
    Reserved8 = 8,
    Reserved9 = 9,
    Reserved10 = 10,
    SVC = 11,
    DebugMon = 12,
    Reserved13 = 13,
    PendSV = 14,
    SysTick = 15,
}

impl From<InternalException> for NvicException {
    fn from(exec: InternalException) -> Self {
        NvicException::from(exec as i32)
    }
}

impl InternalException {
    pub fn from_exception(exception: NvicException) -> Option<InternalException> {
        Some(match exception.num() {
            1 => Self::Reset,
            2 => Self::NonMaskableInterrupt,
            3 => Self::HardFault,
            4 => Self::MemoryManagement,
            5 => Self::BusFault,
            6 => Self::UsageFault,
            7 => Self::Reserved7,
            8 => Self::Reserved8,
            9 => Self::Reserved9,
            10 => Self::Reserved10,
            11 => Self::SVC,
            12 => Self::DebugMon,
            13 => Self::Reserved13,
            14 => Self::PendSV,
            15 => Self::SysTick,
            _ => return None,
        })
    }

    pub fn is_fatal(self) -> bool {
        matches!(
            self,
            Self::HardFault | Self::MemoryManagement | Self::BusFault | Self::UsageFault
        )
    }
}

impl NvicException {
    pub(crate) fn pend(&self) {
        log::trace!("NvicException::pend(self = {})", self);

        // set nvic irq pending
        let nvic = qcontrol_mut()
            .board_mut()
            .expect("fuzz board state is available")
            .nvic_mut()
            .expect("NVIC state is available");
        unsafe {
            qemu_sys::armv7m_nvic_set_pending(nvic as *mut _ as _, self.num(), false);
        }
    }
}

extern "C" fn nvic_abort_hook_rs(exception: i32) {
    let exception = NvicException(exception);
    log::debug!("nvic_abort_hook(exception = {:#x?})", exception);

    crate::hook::hooks()
        .on_exception(exception.into())
        .expect("exception hook failed");

    // break exception loop (hacky early exit condition)
    qcontrol::cpu_mut().parent_obj.crash_occurred = true;

    // make sure we stop after cpu_abort is detected
    crate::qemu::request_stop();
}

pub(crate) fn register_nvic_abort_hook() {
    unsafe {
        qemu_sys::nvic_abort_hook = Some(nvic_abort_hook_rs);
    }
}
