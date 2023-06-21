#[cfg(feature = "arm")]
mod arm;
#[cfg(feature = "arm")]
pub type ArchEmulator = arm::ArmEmulator;
#[cfg(feature = "arm")]
pub type ArchEmulatorSnapshot = arm::ArmEmulatorSnapshot;
