use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec;
use core::ops::{Deref, DerefMut};
use log::{debug, info};
use crate::processor::current_thread;
use crate::signal::ffi::{SIG_MAX, SigAction, Signal, SigSet};
use crate::sync::mutex::Mutex;
use crate::trap::user::dump_tombstone;

pub mod ffi;

#[derive(Copy, Clone)]
pub enum SignalHandler {
    Kernel(fn(Signal)),
    User(SigAction),
}

impl SignalHandler {
    pub fn kernel(signal: Signal) -> Self {
        match signal {
            Signal::SIGCHLD => Self::Kernel(Self::k_ignore),
            Signal::SIGCONT => Self::Kernel(Self::k_ignore),
            _ => Self::Kernel(Self::k_terminate),
        }
    }

    pub fn k_ignore(signal: Signal) {
        debug!("Default signal handler for {:?}: ignore", signal);
    }

    pub fn k_terminate(signal: Signal) {
        info!("Default signal handler for {:?}: terminate", signal);
        #[cfg(feature = "tombstone")]
        dump_tombstone(signal);
        current_thread().terminate(signal as u32 + 128);
    }
}

#[derive(Default, Clone)]
struct SignalQueue {
    queue: VecDeque<Signal>,
    set: SigSet,
}

impl SignalQueue {
    fn push(&mut self, signal: Signal) {
        if !self.set.contains(signal.into()) {
            self.queue.push_back(signal);
            self.set.insert(signal.into());
        }
    }

    fn pop(&mut self) -> Option<Signal> {
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
    waiting_child: bool,
    handlers: Arc<Mutex<[SignalHandler; SIG_MAX]>>,
}

pub struct SignalPoll {
    pub signal: Signal,
    pub handler: SignalHandler,
    pub blocked_before: SigSet,
}

impl SignalControllerInner {
    fn new() -> Self {
        let handlers = core::array::from_fn(|signal| {
            SignalHandler::kernel(signal.try_into().unwrap())
        });
        SignalControllerInner {
            pending: SignalQueue::default(),
            blocked: SigSet::default(),
            waiting_child: false,
            handlers: Arc::new(Mutex::new(handlers)),
        }
    }
}

impl SignalController {
    pub fn new() -> Self {
        Self(Mutex::new(SignalControllerInner::new()))
    }

    pub fn reset(&self) {
        let _ = core::mem::replace(self.0.lock().deref_mut(), SignalControllerInner::new());
    }

    pub fn clone_private(&self) -> Self {
        let inner = self.0.lock();
        let handlers = inner.handlers.lock().deref().clone();
        Self(Mutex::new(SignalControllerInner {
            pending: SignalQueue::default(),
            blocked: inner.blocked.clone(),
            waiting_child: false,
            handlers: Arc::new(Mutex::new(handlers)),
        }))
    }

    pub fn clone_shared(&self) -> Self {
        let inner = self.0.lock();
        Self(Mutex::new(SignalControllerInner {
            pending: SignalQueue::default(),
            blocked: inner.blocked.clone(),
            waiting_child: false,
            handlers: inner.handlers.clone(),
        }))
    }

    /// SAFETY: 该函数只应该由 [Thread::recv_signal] 调用
    pub fn push(&self, signal: Signal) {
        self.0.lock().pending.push(signal);
    }

    pub fn get_mask(&self) -> SigSet {
        self.0.lock().blocked
    }

    pub fn set_mask(&self, mask: SigSet) {
        self.0.lock().blocked = mask.difference(SigSet::SIGKILL | SigSet::SIGSEGV);
    }

    pub fn get_handler(&self, signal: Signal) -> SignalHandler {
        self.0.lock().handlers.lock()[signal as usize]
    }

    pub fn set_handler(&self, signal: Signal, handler: SignalHandler) {
        self.0.lock().handlers.lock()[signal as usize] = handler;
    }

    pub fn set_waiting_child(&self, waiting: bool) {
        self.0.lock().waiting_child = waiting;
    }

    pub fn ignore_on_bus(&self, signal: Signal) -> bool {
        let inner = self.0.lock();
        if signal == Signal::SIGCHLD && inner.waiting_child {
            return false;
        }
        let handler = inner.handlers.lock()[signal as usize];
        inner.blocked.contains(signal.into())
            || matches!(handler, SignalHandler::Kernel(f) if f == SignalHandler::k_ignore)
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
            let handler = inner.handlers.lock()[signal as usize];
            if let SignalHandler::User(sig_action) = &handler {
                inner.blocked |= signal.into();
                inner.blocked |= sig_action.sa_mask;
                inner.blocked -= SigSet::SIGKILL | SigSet::SIGSEGV;
            }

            inner.pending.extend(popped);
            let poll = SignalPoll { signal, handler, blocked_before };
            return Some(poll);
        }

        inner.pending.extend(popped);
        return None;
    }
}
