use core::time::Duration;
use crate::arch;
use crate::board::CLOCK_FREQ;

const MSEC_PER_SEC: usize = 1000;
const TICKS_PER_SEC: usize = 100;

/// 获取当前时间
pub fn current_time() -> Duration {
    let ms = arch::hardware_ts() / (CLOCK_FREQ / MSEC_PER_SEC);
    Duration::from_millis(ms as u64)
}

pub fn set_next_trigger() {
    let next_trigger = arch::hardware_ts() + CLOCK_FREQ / TICKS_PER_SEC;
    arch::set_timer(next_trigger);
}
