use alloc::collections::BinaryHeap;
use core::cmp::Reverse;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use lazy_static::lazy_static;
use pin_project::pin_project;
use crate::sched::time::cpu_time;
use crate::sync::mutex::IrqMutex;

struct Timer {
    expire: Duration,
    waker: Waker,
}

impl Timer {
    fn new(expire: Duration, waker: Waker) -> Self {
        Self { expire, waker }
    }
}

impl PartialEq for Timer {
    fn eq(&self, other: &Self) -> bool {
        self.expire == other.expire
    }
}

impl PartialOrd for Timer {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        self.expire.partial_cmp(&other.expire)
    }
}

impl Eq for Timer {}

impl Ord for Timer {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.expire.cmp(&other.expire)
    }
}

struct TimerQueue(IrqMutex<BinaryHeap<Reverse<Timer>>>);

impl TimerQueue {
    fn push(&self, timer: Timer) {
        self.0.lock().push(Reverse(timer));
    }
}

lazy_static! {
    static ref TIMER_QUEUE: TimerQueue = TimerQueue(IrqMutex::new(BinaryHeap::new()));
}

pub fn sched_timer(expire: Duration, waker: Waker) {
    TIMER_QUEUE.push(Timer::new(expire, waker));
}

pub fn query_timer() -> bool {
    let now = cpu_time();
    let mut queue = TIMER_QUEUE.0.lock();
    if queue.is_empty() {
        return false;
    }
    while let Some(timer) = queue.peek() {
        if timer.0.expire <= now {
            let timer = queue.pop().unwrap();
            timer.0.waker.wake();
        } else {
            break;
        }
    }
    true
}

#[pin_project]
pub struct TimerFuture<F: Fn() -> Duration> {
    trigger: Duration,
    callback: F,
}

impl<F: Fn() -> Duration> TimerFuture<F> {
    pub fn new(trigger: Duration, callback: F) -> Self {
        Self { trigger, callback }
    }
}

impl<F: Fn() -> Duration> Future for TimerFuture<F> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if cpu_time() >= self.trigger {
            self.trigger = (self.callback)();
            if self.trigger.is_zero() {
                return Poll::Ready(());
            }
        }
        sched_timer(self.trigger, cx.waker().clone());
        Poll::Pending
    }
}
