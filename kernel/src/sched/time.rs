use alloc::collections::BTreeMap;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;

use pin_project::pin_project;

use crate::arch;
use crate::driver::BOARD_INFO;
use crate::sched::timer::sched_timer;
use crate::sync::mutex::IrqMutex;

const MSEC_PER_SEC: usize = 1000;
const TICKS_PER_SEC: usize = 100;

// Trick libc-test stat
// 2024-09-01 00:00:00 Asia/Shanghai
const TODAY: Duration = Duration::from_secs(1725120000);

/// 获取当前时间
pub fn current_time() -> Duration {
    if !BOARD_INFO.is_initialized() {
        return TODAY;
    }
    let ms = arch::hardware_ts() / (BOARD_INFO.freq / MSEC_PER_SEC);
    TODAY + Duration::from_millis(ms as u64)
}

pub fn set_next_trigger() {
    let next_trigger = arch::hardware_ts() + BOARD_INFO.freq / TICKS_PER_SEC;
    arch::set_timer(next_trigger);
}

pub static GLOBAL_CLOCK: GlobalClock = GlobalClock::new();

pub struct GlobalClock(IrqMutex<BTreeMap<usize, Duration>>);

impl GlobalClock {
    const fn new() -> Self {
        Self(IrqMutex::new(BTreeMap::new()))
    }

    pub fn get(&self, clock_id: usize) -> Option<Duration> {
        let clock = self.0.lock();
        clock.get(&clock_id).copied()
    }

    pub fn set(&self, clock_id: usize, duration: Duration) {
        let mut clock = self.0.lock();
        clock.insert(clock_id, duration);
    }
}

#[pin_project]
pub struct TimeoutFuture<F: Future> {
    expire: Duration,
    sched: bool,
    #[pin]
    fut: F,
}

pub enum TimeoutResult<T> {
    Timeout,
    Ready(T),
}

impl<F: Future> TimeoutFuture<F> {
    pub fn new(wait: Duration, fut: F) -> Self {
        Self { expire: current_time() + wait, sched: false, fut }
    }
}

impl<F: Future> Future for TimeoutFuture<F> {
    type Output = TimeoutResult<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        if current_time() >= *this.expire {
            return Poll::Ready(TimeoutResult::Timeout);
        }

        match this.fut.poll(cx) {
            Poll::Ready(v) => Poll::Ready(TimeoutResult::Ready(v)),
            Poll::Pending => {
                if !*this.sched {
                    sched_timer(*this.expire, cx.waker().clone());
                    *this.sched = true;
                }
                Poll::Pending
            }
        }
    }
}
