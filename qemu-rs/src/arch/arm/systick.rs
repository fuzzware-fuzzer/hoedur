use std::os;

use qemu_sys::{cstr, ARMv7MState};

use crate::{Event, QemuCallbackShared};

const SYST_RELOAD_VAL_MASK: u32 = 0x00ff_ffff;

const REG_OFF_SYST_CSR: u64 = 0x0;
const REG_OFF_SYST_RVR: u64 = 0x4;
const REG_OFF_SYST_CVR: u64 = 0x8;
const REG_OFF_SYST_CALIB: u64 = 0xc;

const SYST_CSR_ENABLE: u32 = 1 << 0;
const SYST_CSR_TICKINT: u32 = 1 << 1;
const SYST_CSR_CLKSOURCE: u32 = 1 << 2;
const SYST_CSR_COUNTFLAG: u32 = 1 << 16;

const SYSTICK_1_MS: u32 = 15_000;
const SYSTICK_SCALE: u32 = SYSTICK_1_MS / 10;
const SYSTICK_CALIBRATION_VALUE: u32 = 10 * SYSTICK_1_MS; // "10ms"
const SYSTICK_MIN_VALUE: u32 = 500;
const SYSTICK_MAX_VALUE: u32 = 1_500;

static mut SYSTICK: Option<SysTick> = None;

pub struct SysTick {
    region: qemu_sys::MemoryRegion,
    ops: qemu_sys::MemoryRegionOps,
    callback: QemuCallbackShared,

    enabled: bool,
    interrupt: bool,
    core_clock: bool,
    count_flag: bool,
    reload_value: u32,
    ticks: Option<u32>,
}

#[derive(Clone, Debug)]
pub(crate) struct SysTickSnapshot {
    enabled: bool,
    interrupt: bool,
    core_clock: bool,
    count_flag: bool,
    reload_value: u32,
    ticks: Option<u32>,
}

pub fn systick() -> &'static mut SysTick {
    unsafe { SYSTICK.as_mut().unwrap() }
}

fn systick_ptr<'a>(opaque: *mut os::raw::c_void) -> &'a mut SysTick {
    let systick = unsafe { (opaque as *mut SysTick).as_mut() }
        .expect("SysTick is null, this should never happen");

    #[cfg(debug_assertions)]
    unsafe {
        debug_assert_eq!(
            Some(systick as *mut _),
            SYSTICK.as_mut().map(|systick| systick as *mut _)
        );
    }

    systick
}

extern "C" fn systick_read(
    opaque: *mut os::raw::c_void,
    addr: qemu_sys::hwaddr,
    size: os::raw::c_uint,
) -> u64 {
    if size != 4 {
        log::warn!(
            "Invalid SysTick read with size {} at offset {:#x?}",
            size,
            addr
        );
        return 0;
    };

    let value = systick_ptr(opaque).read(addr);

    log::debug!(
        "systick_read(opaque = {:#x?}, addr = {:#x?}, size = {:#x?}) -> value = {:#x?}",
        opaque,
        addr,
        size,
        value
    );

    value as u64
}

extern "C" fn systick_write(
    opaque: *mut os::raw::c_void,
    addr: qemu_sys::hwaddr,
    data: u64,
    size: os::raw::c_uint,
) {
    if size != 4 {
        log::warn!(
            "Invalid SysTick write with size {} at offset {:#x?} with value {:#x?}",
            size,
            addr,
            data
        );
    }

    log::trace!(
        "systick_write(opaque = {:#x?}, addr = {:#x?}, data = {:#x?}, size = {:#x?})",
        opaque,
        addr,
        data,
        size
    );

    systick_ptr(opaque).write(addr, data as u32);
}

impl SysTick {
    fn new(
        region: qemu_sys::MemoryRegion,
        ops: qemu_sys::MemoryRegionOps,
        callback: QemuCallbackShared,
    ) -> Self {
        SysTick {
            region,
            ops,
            callback,
            enabled: false,
            interrupt: false,
            core_clock: false,
            count_flag: false,
            ticks: None,
            reload_value: SYSTICK_MIN_VALUE,
        }
    }

    pub fn tick(&mut self, count: u32) -> bool {
        if !self.enabled || count == 0 {
            return false;
        }

        log::trace!("self.ticks = {:?}, count = {}", self.ticks, count);

        if let Some(ticks) = &mut self.ticks {
            let (value, overflow) = ticks.overflowing_sub(count);
            debug_assert!(!overflow);

            if value > 0 && !overflow {
                *ticks = value;
            } else {
                self.count_flag = true;
                self.ticks = Some(self.reload_value);

                if self.interrupt {
                    return true;
                }
            }
        }

        false
    }

    pub fn ticks(&self) -> Option<u32> {
        self.ticks
    }

    fn reload(&mut self) {
        self.request_update(Event::SysTickGetTicks);
        self.ticks = Some(self.reload_value);
        self.request_update(Event::SysTickChanged);
    }

    fn request_update(&mut self, event: Event) {
        self.callback
            .borrow_mut()
            .on_update(event)
            .expect("update hook failed");
    }

    fn csr(&self) -> u32 {
        [
            self.enabled.then_some(SYST_CSR_ENABLE),
            self.interrupt.then_some(SYST_CSR_TICKINT),
            self.core_clock.then_some(SYST_CSR_CLKSOURCE),
            self.count_flag.then_some(SYST_CSR_COUNTFLAG),
        ]
        .iter()
        .flatten()
        .sum()
    }

    fn read(&mut self, offset: u64) -> u32 {
        // SysTick register read
        match offset {
            REG_OFF_SYST_CSR => {
                // Simply return value here
                let value = self.csr();

                /*
                 * HACK (non-standard behavior):
                 * In case firmware explicitly asks whether time has passed
                 * multiple times within one systick period, indicate that it has.
                 * This makes time go faster for firmware waiting in busy loops via
                 * a SysTick polling mechanism (which we want it to get out of).
                 */
                self.count_flag = true;

                value
            }
            REG_OFF_SYST_RVR => {
                // Strictly speaking only 24 bits are used for the reload val
                (self.reload_value * SYSTICK_SCALE) & SYST_RELOAD_VAL_MASK
            }
            REG_OFF_SYST_CVR => {
                // Strictly speaking only 24 bits are used for the reload val
                self.request_update(Event::SysTickGetTicks);
                (self.ticks.unwrap_or(0) * SYSTICK_SCALE) & SYST_RELOAD_VAL_MASK
            }
            REG_OFF_SYST_CALIB => SYSTICK_CALIBRATION_VALUE,
            _ => {
                log::warn!("Invalid SysTick read at offset {:#x?}", offset);
                0
            }
        }
    }

    fn write(&mut self, offset: u64, value: u32) {
        match offset {
            REG_OFF_SYST_CSR => {
                // SysTick is only concerned with writing the 3 lowest bits
                // ENABLE, TICKINT, CLKSOURCE
                let enabled = value & SYST_CSR_ENABLE != 0;
                let interrupt = value & SYST_CSR_TICKINT != 0;
                let core_clock = value & SYST_CSR_CLKSOURCE != 0;

                // Did the enable status change?
                // Did the clock source change?
                if enabled && (!self.enabled || core_clock != self.core_clock) {
                    self.reload();
                }

                self.enabled = enabled;
                self.interrupt = interrupt;
                self.core_clock = core_clock;
                // We will react to TICKINT as soon as the timer expires
            }
            REG_OFF_SYST_RVR => {
                // restrict the value to something that makes sense to the emulator
                let ticks = (value / SYSTICK_SCALE).clamp(SYSTICK_MIN_VALUE, SYSTICK_MAX_VALUE);

                log::debug!(
                    "set reload_value: value = {:#x?}, ticks = {:#x?}",
                    value,
                    ticks
                );

                // The timer will handle the invalid case 0 by itself
                self.reload_value = ticks & SYST_RELOAD_VAL_MASK;
            }
            REG_OFF_SYST_CVR => {
                // Clear COUNTFLAG
                self.count_flag = false;
                // Clear current value to 0, meaning a timer reset
                self.reload();
            }
            _ => log::warn!(
                "Invalid SysTick write at offset {:#x?} with value {:#x?}",
                offset,
                value
            ),
        }
    }

    pub(crate) fn snapshot_create(&self) -> SysTickSnapshot {
        SysTickSnapshot {
            enabled: self.enabled,
            interrupt: self.interrupt,
            core_clock: self.core_clock,
            count_flag: self.count_flag,
            reload_value: self.reload_value,
            ticks: self.ticks,
        }
    }

    pub(crate) fn snapshot_restore(&mut self, snapshot: &SysTickSnapshot) {
        self.enabled = snapshot.enabled;
        self.interrupt = snapshot.interrupt;
        self.core_clock = snapshot.core_clock;
        self.count_flag = snapshot.count_flag;
        self.reload_value = snapshot.reload_value;
        self.ticks = snapshot.ticks;
    }
}

pub(crate) fn init_systick(
    dev: *mut qemu_sys::DeviceState,
    armv7m: &mut ARMv7MState,
    callback: QemuCallbackShared,
) {
    log::trace!("init_systick()");

    let region = qemu_sys::MemoryRegion::default();
    let ops = qemu_sys::MemoryRegionOps {
        read: Some(systick_read),
        write: Some(systick_write),
        endianness: qemu_sys::device_endian::DEVICE_NATIVE_ENDIAN,
        valid: qemu_sys::MemoryRegionOps__bindgen_ty_1 {
            min_access_size: 4,
            max_access_size: 4,
            ..qemu_sys::MemoryRegionOps__bindgen_ty_1::default()
        },
        ..qemu_sys::MemoryRegionOps::default()
    };

    // shadow qemu systick impl
    unsafe {
        SYSTICK = Some(SysTick::new(region, ops, callback));
        let systick_ptr = SYSTICK.as_mut().unwrap();

        qemu_sys::memory_region_init_io(
            &mut systick_ptr.region,
            dev as _,
            &systick_ptr.ops,
            systick_ptr as *mut _ as _,
            cstr!("nvic_systick-hoedur"),
            // NOTE: QEMU uses 0xe0 to include reserved area 0xE000E020-0xE000E0FC
            0x10,
        );
        qemu_sys::memory_region_add_subregion_overlap(
            &mut armv7m.container,
            0xe000e010,
            &mut systick_ptr.region,
            i32::MAX,
        );
    }
}

pub(crate) fn drop_systick() {
    unsafe {
        SYSTICK.take();
    }
}
