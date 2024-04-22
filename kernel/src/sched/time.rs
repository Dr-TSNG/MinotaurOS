use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;

use pin_project::pin_project;

use crate::arch;
use crate::driver::BOARD_INFO;
use crate::sched::timer::sched_timer;

const MSEC_PER_SEC: usize = 1000;
const TICKS_PER_SEC: usize = 100;

/// 获取当前时间
pub fn current_time() -> Duration {
    if !BOARD_INFO.is_initialized() {
        return Duration::from_millis(0);
    }
    let ms = arch::hardware_ts() / (BOARD_INFO.freq / MSEC_PER_SEC);
    Duration::from_millis(ms as u64)
}

pub fn set_next_trigger() {
    let next_trigger = arch::hardware_ts() + BOARD_INFO.freq / TICKS_PER_SEC;
    arch::set_timer(next_trigger);
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
    pub fn new(expire: Duration, fut: F) -> Self {
        Self { expire, sched: false, fut }
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
