use alloc::collections::BinaryHeap;
use core::cmp::Reverse;
use core::task::Waker;
use core::time::Duration;
use lazy_static::lazy_static;
use crate::sched::time::current_time;
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
    let now = current_time();
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
