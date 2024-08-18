use core::sync::atomic::AtomicU32;

pub mod jh7110;
// mod regs;

static MMC_COUNTER: AtomicU32 = AtomicU32::new(0);

fn wait_until(mut cond: impl FnMut() -> bool) {
    let mut timeout = 100000;
    while !cond() && timeout > 0 {
        core::hint::spin_loop();
        timeout -= 1;
    }
}
