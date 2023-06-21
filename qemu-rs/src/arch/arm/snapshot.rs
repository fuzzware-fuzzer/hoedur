use std::{
    fmt,
    ptr::{slice_from_raw_parts, slice_from_raw_parts_mut},
};

use anyhow::{bail, Context, Result};
use qemu_sys::{arm_feature, arm_features};

use crate::{fuzz::machine::Cpu, systick::SysTickSnapshot};

const M_REG_NS: usize = 0;
const M_REG_S: usize = 1;

#[derive(Debug, Clone)]
pub(crate) struct ArmCpuSnapshot {
    pub pmsa: PMSA,
    pub sau: Option<SAU>,
}

#[derive(Debug, Clone)]
pub enum PMSA {
    V7(PMSAv7),
    V8(PMSAv8, Option<PMSAv8>),
    Disabled,
}

#[derive(Debug, Clone)]
pub struct PMSAv7 {
    pub drbar: Vec<u32>,
    pub drsr: Vec<u32>,
    pub dracr: Vec<u32>,
    pub rnr: [u32; 2],
}

#[derive(Debug, Clone)]
pub struct PMSAv8 {
    pub rbar: Vec<u32>,
    pub rlar: Vec<u32>,
    pub mair0: u32,
    pub mair1: u32,
}

#[derive(Debug, Clone)]
pub struct SAU {
    pub rbar: Vec<u32>,
    pub rlar: Vec<u32>,
    pub rnr: u32,
    pub ctrl: u32,
}

#[derive(Clone)]
pub(crate) struct NvicSnapshot {
    vectors: [qemu_sys::VecInfo; 512],
    prigroup: [u32; 2],
    security: Option<NvicSecuritySnapshot>,
    systick: SysTickSnapshot,
}

impl fmt::Debug for NvicSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NvicSnapshot")
            .field("vectors", &NvicVectors(&self.vectors))
            .field("prigroup", &self.prigroup)
            .field("security", &self.security)
            .field("systick", &self.systick)
            .finish()
    }
}

#[derive(Clone)]
struct NvicSecuritySnapshot {
    sec_vectors: [qemu_sys::VecInfo; 16usize],
    itns: [bool; 512usize],
}

impl fmt::Debug for NvicSecuritySnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NvicSecuritySnapshot")
            .field("sec_vectors", &NvicVectors(&self.sec_vectors))
            .field("itns", &SecureVectors(&self.itns))
            .finish()
    }
}

impl ArmCpuSnapshot {
    pub(crate) fn create(cpu: &Cpu) -> Self {
        let env = &cpu.env;

        // verify unsupported boot info / GICv3 is not present
        debug_assert!(env.boot_info.is_null());
        debug_assert!(env.gicv3state.is_null());

        // add MPU data to snapshot
        let len = cpu.pmsav7_dregion as usize;
        let pmsa = if arm_feature(env, arm_features::ARM_FEATURE_PMSA) && len > 0 {
            if arm_feature(env, arm_features::ARM_FEATURE_V8) {
                // PMSAv8
                PMSA::V8(
                    PMSAv8 {
                        rbar: save_into_vec(env.pmsav8.rbar[M_REG_NS], len),
                        rlar: save_into_vec(env.pmsav8.rlar[M_REG_NS], len),
                        mair0: env.pmsav8.mair0[M_REG_NS],
                        mair1: env.pmsav8.mair1[M_REG_NS],
                    },
                    arm_feature(env, arm_features::ARM_FEATURE_M_SECURITY).then(|| PMSAv8 {
                        rbar: save_into_vec(env.pmsav8.rbar[M_REG_S], len),
                        rlar: save_into_vec(env.pmsav8.rlar[M_REG_S], len),
                        mair0: env.pmsav8.mair0[M_REG_S],
                        mair1: env.pmsav8.mair1[M_REG_S],
                    }),
                )
            } else if arm_feature(env, arm_features::ARM_FEATURE_V7) {
                // PMSAv7
                PMSA::V7(PMSAv7 {
                    drbar: save_into_vec(env.pmsav7.drbar, len),
                    drsr: save_into_vec(env.pmsav7.drsr, len),
                    dracr: save_into_vec(env.pmsav7.dracr, len),
                    rnr: env.pmsav7.rnr,
                })
            } else {
                PMSA::Disabled
            }
        } else {
            PMSA::Disabled
        };

        // add SAU data to snapshot
        let len = cpu.sau_sregion as usize;
        let sau = arm_feature(env, arm_features::ARM_FEATURE_M_SECURITY).then(|| SAU {
            rbar: save_into_vec(env.sau.rbar, len),
            rlar: save_into_vec(env.sau.rlar, len),
            rnr: env.sau.rnr,
            ctrl: env.sau.ctrl,
        });

        Self { pmsa, sau }
    }

    pub(crate) fn restore(&self, cpu: &mut Cpu) {
        let env = &mut cpu.env;
        let mut tlb_flush = false;

        // PMSA
        match &self.pmsa {
            PMSA::V7(pmsav7) => {
                tlb_flush |= pmsav7.restore(env);
            }
            PMSA::V8(pmsav8, pmsav8_security) => {
                tlb_flush |= pmsav8.restore(env, M_REG_NS);

                if let Some(pmsav8_security) = &pmsav8_security {
                    tlb_flush |= pmsav8_security.restore(env, M_REG_S);
                }
            }
            PMSA::Disabled => {}
        }

        // SAU
        if let Some(sau) = &self.sau {
            for (dst, src) in [(env.sau.rbar, &sau.rbar), (env.sau.rlar, &sau.rlar)] {
                tlb_flush |= restore_from_slice(dst, src);
            }
            tlb_flush |= restore(&mut env.sau.rnr, &sau.rnr);
            tlb_flush |= restore(&mut env.sau.ctrl, &sau.ctrl);
        }

        // flush TLB after restore
        if tlb_flush {
            log::trace!("TLB flush required after PMSA/SAU snapshot restore");

            unsafe {
                qemu_sys::tlb_flush(&mut cpu.parent_obj);
            }
        }
    }
}

impl PMSAv7 {
    fn restore(&self, env: &mut qemu_sys::CPUArchState) -> bool {
        let mut tlb_flush = false;

        for (dst, src) in [
            (env.pmsav7.drbar, &self.drbar),
            (env.pmsav7.drsr, &self.drsr),
            (env.pmsav7.dracr, &self.dracr),
        ] {
            tlb_flush |= restore_from_slice(dst, src);
        }

        tlb_flush |= restore(&mut env.pmsav7.rnr, &self.rnr);

        tlb_flush
    }
}

impl PMSAv8 {
    fn restore(&self, env: &mut qemu_sys::CPUArchState, index: usize) -> bool {
        let mut tlb_flush = false;

        for (dst, src) in [
            (env.pmsav8.rbar[index], &self.rbar),
            (env.pmsav8.rlar[index], &self.rlar),
        ] {
            tlb_flush |= restore_from_slice(dst, src);
        }

        tlb_flush |= restore(&mut env.pmsav8.mair0[index], &self.mair0);
        tlb_flush |= restore(&mut env.pmsav8.mair1[index], &self.mair1);

        tlb_flush
    }
}

fn save_into_vec<T: Copy>(array: *const T, len: usize) -> Vec<T> {
    unsafe { &*slice_from_raw_parts(array, len) }.to_vec()
}

#[must_use]
fn restore_from_slice<T: Copy + Eq>(array: *mut T, vec: &[T]) -> bool {
    let dst = unsafe { &mut *slice_from_raw_parts_mut(array, vec.len()) };

    if dst != vec {
        dst.copy_from_slice(vec);
        return true;
    }

    false
}

fn restore<T: Copy + Eq>(dst: &mut T, src: &T) -> bool {
    if dst != src {
        *dst = *src;
        return true;
    }

    false
}

impl NvicSnapshot {
    pub(crate) fn create(nvic: &qemu_sys::NVICState) -> Self {
        Self {
            vectors: nvic.vectors,
            prigroup: nvic.prigroup,
            security: NvicSecuritySnapshot::create(nvic),
            systick: crate::systick().snapshot_create(),
        }
    }

    pub(crate) fn restore(&self, nvic: &mut qemu_sys::NVICState) -> Result<()> {
        // restore NVIC irq state
        nvic.vectors = self.vectors;
        nvic.prigroup = self.prigroup;

        // restore secure part of NVIC
        if let Some(security) = &self.security {
            security.restore(nvic).context("NVIC security restore")?;
        }

        // recalculate NVIC state
        if unsafe { qemu_sys::nvic_post_load(nvic as *mut _ as *mut _, 0) } != 0 {
            bail!("nvic_post_load failed")
        }

        // restore SysTick
        crate::systick().snapshot_restore(&self.systick);

        Ok(())
    }
}

impl NvicSecuritySnapshot {
    fn create(nvic: &qemu_sys::NVICState) -> Option<Self> {
        if arm_feature(
            &unsafe { *nvic.cpu }.env,
            arm_features::ARM_FEATURE_M_SECURITY,
        ) {
            Some(Self {
                sec_vectors: nvic.sec_vectors,
                itns: nvic.itns,
            })
        } else {
            None
        }
    }

    fn restore(&self, nvic: &mut qemu_sys::NVICState) -> Result<()> {
        // restore NVIC secure irq state
        nvic.sec_vectors = self.sec_vectors;
        nvic.itns = self.itns;

        // recalculate NVIC secure state
        if unsafe { qemu_sys::nvic_security_post_load(nvic as *mut _ as *mut _, 0) } != 0 {
            bail!("nvic_security_post_load failed")
        }

        Ok(())
    }
}

struct NvicVectors<'a, const N: usize>(&'a [qemu_sys::VecInfo; N]);

impl<'a, const N: usize> fmt::Debug for NvicVectors<'a, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();

        for (num, info) in self.0.iter().enumerate() {
            if info.prio == 0
                && info.enabled == 0
                && info.pending == 0
                && info.active == 0
                && info.level == 0
            {
                continue;
            }

            map.entry(&num, info);
        }

        map.finish()
    }
}

struct SecureVectors<'a, const N: usize>(&'a [bool; N]);

impl<'a, const N: usize> fmt::Debug for SecureVectors<'a, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut set = f.debug_set();

        for (num, secure) in self.0.iter().enumerate() {
            if *secure {
                set.entry(&num);
            }
        }

        set.finish()
    }
}
