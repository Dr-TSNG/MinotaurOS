use core::sync::atomic::AtomicU32;

pub mod jh7110;
// mod regs;

static MMC_COUNTER: AtomicU32 = AtomicU32::new(0);
