use alloc::sync::Arc;
use core::cell::UnsafeCell;
use log::info;
use crate::process::Process;
use crate::process::thread::event_bus::{Event, EventBus};
use crate::process::thread::resource::ResourceUsage;
use crate::process::thread::tid::TidTracker;
use crate::signal::ffi::Signal;
use crate::signal::SignalController;
use crate::trap::context::TrapContext;

pub mod event_bus;
pub mod resource;
pub mod tid;

/// 线程 TCB
pub struct Thread {
    pub tid: Arc<TidTracker>,
    pub process: Arc<Process>,
    pub signals: SignalController,
    pub event_bus: EventBus,
    inner: UnsafeCell<ThreadInner>,
}

pub struct ThreadInner {
    pub trap_ctx: TrapContext,
    pub tid_address: TidAddress,
    pub rusage: ResourceUsage,
    pub exit_code: Option<i8>,
}

#[derive(Default)]
pub struct TidAddress {
    pub set_tid_address: Option<usize>,
    pub clear_tid_address: Option<usize>,
}

unsafe impl Send for Thread {}

unsafe impl Sync for Thread {}

impl Thread {
    pub fn new(
        process: Arc<Process>,
        trap_ctx: TrapContext,
        tid: Option<Arc<TidTracker>>,
        signals: SignalController,
    ) -> Arc<Self> {
        let tid = tid.unwrap_or(Arc::new(TidTracker::new()));
        let inner = ThreadInner {
            trap_ctx,
            tid_address: TidAddress::default(),
            rusage: ResourceUsage::new(),
            exit_code: None,
        };
        let thread = Thread {
            tid,
            process,
            signals,
            event_bus: EventBus::default(),
            inner: UnsafeCell::new(inner),
        };
        Arc::new(thread)
    }

    /// SAFETY: ThreadInner 中的成员在 spawn 后只应该被本地 hart 访问
    pub fn inner(&self) -> &mut ThreadInner {
        unsafe { &mut *self.inner.get() }
    }

    pub fn recv_signal(&self, signal: Signal) {
        info!("Thread {} receive signal {:?}", self.tid.0, signal);
        match signal {
            Signal::SIGCHLD => self.event_bus.recv_event(Event::CHILD_EXIT),
            Signal::SIGKILL => self.event_bus.recv_event(Event::KILL_THREAD),
            _ => {
                if !self.signals.get_mask().contains(signal.into()) {
                    self.event_bus.recv_event(Event::COMMON_SIGNAL);
                }
            }
        }
        self.signals.push(signal);
    }

    pub fn terminate(&self, exit_code: i8) {
        let mut proc_inner = self.process.inner.lock();
        proc_inner.threads.remove(&self.tid.0);
        self.inner().exit_code = Some(exit_code);
    }

    pub fn on_exit(self: Arc<Self>) {
        let exit_code = self.inner().exit_code.unwrap();
        self.process.on_thread_exit(self.tid.0, exit_code);
    }
}
