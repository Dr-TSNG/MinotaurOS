use core::time::Duration;
use crate::arch::hardware_ts;
use crate::board::CLOCK_FREQ;

const MSEC_PER_SEC: usize = 1000;

/// 获取当前时间
pub fn current_time() -> Duration {
    let ms = hardware_ts() / (CLOCK_FREQ / MSEC_PER_SEC);
    Duration::from_millis(ms as u64)
}
