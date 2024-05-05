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


# 关于Box::pin()
在udp.rs的connect()函数中，调用connect()函数会在其中使用到Box::pin返回
Pin<Box<impl Future<Output=Result<i32, <unknown>（生命周期'a）>>+Sized>>
这个返回值时一个future，可以被runtime执行。

现在的实现返回值时错误的，要实现和异步runtime和系统调用的接轨。



