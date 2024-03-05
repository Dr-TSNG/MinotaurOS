use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::task::Waker;
use crate::process::Process;
use crate::process::thread::resource::ResourceUsage;
use crate::process::thread::tid::TidTracker;
use crate::trap::context::TrapContext;

pub mod resource;
pub mod tid;

/// 线程 TCB
pub struct Thread {
    pub tid: Arc<TidTracker>,
    pub process: Arc<Process>,
    inner: UnsafeCell<ThreadInner>,
}

pub struct ThreadInner {
    pub trap_ctx: TrapContext,
    pub rusage: ResourceUsage,
    pub waker: Option<Waker>,
    pub ustack_top: usize,
    pub terminated: bool,
}

unsafe impl Send for Thread {}
unsafe impl Sync for Thread {}

impl Thread {
    pub fn new(
        process: Arc<Process>,
        trap_ctx: TrapContext,
        ustack_top: usize,
        tid: Option<Arc<TidTracker>>,
    ) -> Self {
        let tid = tid.unwrap_or(Arc::new(TidTracker::new()));
        let inner = ThreadInner {
            trap_ctx,
            rusage: ResourceUsage::new(),
            waker: None,
            ustack_top,
            terminated: false,
        };
        Thread {
            tid,
            process,
            inner: UnsafeCell::new(inner),
        }
    }
    
    /// SAFETY: ThreadInner 中的成员在 spawn 后只应该被本地 hart 访问
    pub fn inner(&self) -> &mut ThreadInner {
        unsafe { &mut *self.inner.get() }
    }
    
    pub fn on_terminate(self: Arc<Self>) {
        
    }
}
