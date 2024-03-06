use core::time::Duration;
use crate::arch::{hardware_ts, set_timer};
use crate::board::CLOCK_FREQ;

const MSEC_PER_SEC: usize = 1000;
const INTERRUPT_FREQ: usize = 100;

/// 获取当前时间
pub fn current_time() -> Duration {
    let ms = hardware_ts() / (CLOCK_FREQ / MSEC_PER_SEC);
    Duration::from_millis(ms as u64)
}

pub fn set_next_trigger() {
    let next_trigger = hardware_ts() + CLOCK_FREQ / INTERRUPT_FREQ;
    set_timer(next_trigger);
}
