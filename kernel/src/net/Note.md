# in config.rs
current_time_duration().as_millis() as i64 为 

/// 获取当前时间
pub fn current_time() -> Duration {
    if !BOARD_INFO.is_initialized() {
        return Duration::from_millis(0);
    }
    let ms = arch::hardware_ts() / (BOARD_INFO.freq / MSEC_PER_SEC);
    Duration::from_millis(ms as u64)
}

在别人的实现中：
/// get current time in microseconds
pub fn current_time_us() -> usize {
    time::read() / (CLOCK_FREQ / USEC_PER_SEC)
}
/// get current time in `Duration`
pub fn current_time_duration() -> Duration {
    Duration::from_micros(current_time_us() as u64)
}

这两个事件都使用Duration表示，转化为Duration后是否完全一致呢？


# 

