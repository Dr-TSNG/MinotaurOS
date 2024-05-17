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


# 关于文件系统与Socket之间的关联
在TcpSocket::new()中，最终返回的情况是：

Self {
    socket_handle: handler,
    inner: Mutex::new(TcpInner {
        local_endpoint: IpListenEndpoint { addr: None, port },
        remote_endpoint: None,
        last_state: tcp::State::Closed,
        recv_buf_size: BUFFER_SIZE,
        send_buf_size: BUFFER_SIZE,
    }),
    file_data: FileMeta::new(),
}

中的FileMeta::new()如何创建Inode节点。

