use alloc::collections::VecDeque;
use alloc::vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use log::{debug, info};
use crate::signal::ffi::{SIG_MAX, SigAction, Signal, SigSet};
use crate::sync::mutex::Mutex;

pub mod ffi;

#[derive(Copy, Clone)]
pub enum SignalHandler {
    Kernel(fn(Signal)),
    User(SigAction),
}

impl SignalHandler {
    pub fn kernel(signal: Signal) -> Self {
        match signal {
            Signal::SIGHUP => Self::Kernel(Self::k_terminate),
            Signal::SIGINT => Self::Kernel(Self::k_terminate),
            Signal::SIGILL => Self::Kernel(Self::k_terminate),
            Signal::SIGABRT => Self::Kernel(Self::k_terminate),
            Signal::SIGBUS => Self::Kernel(Self::k_terminate),
            Signal::SIGKILL => Self::Kernel(Self::k_terminate),
            Signal::SIGSEGV => Self::Kernel(Self::k_terminate),
            Signal::SIGALRM => Self::Kernel(Self::k_terminate),
            Signal::SIGTERM => Self::Kernel(Self::k_terminate),
            Signal::SIGCHLD => Self::Kernel(Self::k_terminate),
            Signal::SIGSTOP => Self::Kernel(Self::k_terminate),
            _ => Self::Kernel(Self::k_ignore),
        }
    }

    pub fn k_ignore(signal: Signal) {
        debug!("Default signal handler for {:?}: ignore", signal);
    }

    pub fn k_terminate(signal: Signal) {
        info!("Default signal handler for {:?}: terminate", signal);
        // current_process.terminate(-1);
    }
}

#[derive(Default)]
pub struct SignalQueue {
    queue: VecDeque<Signal>,
    set: SigSet,
}

impl SignalQueue {
    pub fn push(&mut self, signal: Signal) {
        if !self.set.contains(signal.into()) {
            self.queue.push_back(signal);
            self.set.insert(signal.into());
        }
    }

    pub fn pop(&mut self) -> Option<Signal> {
        self.queue.pop_front().inspect(|s| self.set.remove((*s).into()))
    }
}

impl Extend<Signal> for SignalQueue {
    fn extend<T: IntoIterator<Item=Signal>>(&mut self, iter: T) {
        for v in iter.into_iter() {
            self.push(v);
        }
    }
}

pub struct SignalController(Mutex<SignalControllerInner>);

struct SignalControllerInner {
    pending: SignalQueue,
    blocked: SigSet,
    waker: Option<Waker>,
    handlers: [SignalHandler; SIG_MAX],
}

pub struct SignalPoll {
    pub signal: Signal,
    pub handler: SignalHandler,
    pub blocked_before: SigSet,
}

impl SignalController {
    pub fn new() -> Self {
        let inner = SignalControllerInner {
            pending: SignalQueue::default(),
            blocked: SigSet::default(),
            waker: None,
            handlers: core::array::from_fn(|signal| SignalHandler::kernel(signal.try_into().unwrap())),
        };
        Self(Mutex::new(inner))
    }

    pub fn recv_signal(&self, signal: Signal) {
        debug!("Receive signal {:?}", signal);
        let mut inner = self.0.lock();
        inner.pending.push(signal);
        if let Some(waker) = inner.waker.take() {
            debug!("Invoke signal waker");
            waker.wake_by_ref();
        }
    }

    pub fn get_mask(&self) -> SigSet {
        self.0.lock().blocked
    }

    pub fn set_mask(&self, mask: SigSet) {
        self.0.lock().blocked = mask;
    }

    pub fn get_handler(&self, signal: Signal) -> SignalHandler {
        self.0.lock().handlers[signal as usize]
    }

    pub fn set_handler(&self, signal: Signal, handler: SignalHandler) {
        self.0.lock().handlers[signal as usize] = handler;
    }

    pub fn poll(&self) -> Option<SignalPoll> {
        let mut inner = self.0.lock();
        let mut popped = vec![];
        while let Some(signal) = inner.pending.pop() {
            if inner.blocked.contains(signal.into()) {
                debug!("Signal {:?} is blocked", signal);
                popped.push(signal);
                continue;
            }
            let blocked_before = inner.blocked;
            let handler = inner.handlers[signal as usize];
            if let SignalHandler::User(sig_action) = &handler {
                inner.blocked.insert(signal.into());
                inner.blocked |= sig_action.sa_mask;
            }

            inner.pending.extend(popped);
            let poll = SignalPoll { signal, handler, blocked_before };
            return Some(poll);
        }

        inner.pending.extend(popped);
        return None;
    }

    pub async fn suspend(&self) {
        WaitSignalFuture(self).await;
    }
}

struct WaitSignalFuture<'a>(&'a SignalController);

impl<'a> Future for WaitSignalFuture<'a> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut inner = self.0.0.lock();
        if !inner.pending.set.is_empty() {
            return Poll::Ready(());
        }
        inner.waker.replace(cx.waker().clone());
        Poll::Pending
    }
}
