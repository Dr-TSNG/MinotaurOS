use alloc::sync::Arc;
use core::cell::SyncUnsafeCell;
use hashbrown::HashSet;
use log::{debug, info, warn};
use smart_default::SmartDefault;
use crate::arch::VirtAddr;
use crate::fs::inode::FCap;
use crate::mm::protect::user_transmute_w;
use crate::process::ffi::{CapSet, CpuSet};
use crate::process::{Gid, Process, Uid};
use crate::process::thread::event_bus::{Event, EventBus};
use crate::process::thread::resource::ResourceUsage;
use crate::process::thread::tid::TidTracker;
use crate::signal::ffi::Signal;
use crate::signal::SignalController;
use crate::sync::mutex::Mutex;
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
    pub cpu_set: Mutex<CpuSet>,
    inner: SyncUnsafeCell<ThreadInner>,
}

pub struct ThreadInner {
    pub trap_ctx: TrapContext,
    pub audit: Audit,
    pub sys_can_restart: bool,
    pub sys_last_a0: usize,
    pub tid_address: TidAddress,
    pub rusage: ResourceUsage,
    pub vfork_from: Option<Arc<Thread>>,
    pub exit_code: Option<u32>,
}

#[derive(Clone, Default)]
pub struct Audit {
    pub ruid: Uid,
    pub euid: Uid,
    pub suid: Uid,
    pub rgid: Gid,
    pub egid: Gid,
    pub sgid: Gid,
    pub sup_gids: HashSet<Gid>,
    pub caps: PCap,
}

#[derive(Clone, SmartDefault)]
pub struct PCap {
    #[default(CapSet::all())]
    pub permitted: CapSet,
    #[default(CapSet::all())]
    pub inheritable: CapSet,
    #[default(CapSet::all())]
    pub effective: CapSet,
    #[default(CapSet::all())]
    pub bounding: CapSet,
    #[default(CapSet::all())]
    pub ambient: CapSet,
}

impl PCap {
    pub fn execve(&mut self, f_pri: bool, fcap: &FCap) {
        *self = Self {
            ambient: if f_pri { CapSet::empty() } else { self.ambient },
            permitted: (self.inheritable & fcap.inheritable) | (fcap.permitted & self.bounding) | self.ambient,
            effective: (self.permitted & fcap.effective) | (self.ambient & !fcap.effective),
            inheritable: self.inheritable,
            bounding: self.bounding,
        };
    }
}

#[derive(Default)]
pub struct TidAddress {
    pub set: Option<VirtAddr>,
    pub clear: Option<VirtAddr>,
}

impl Thread {
    pub fn new(
        process: Arc<Process>,
        trap_ctx: TrapContext,
        token_set: Audit,
        tid: Option<Arc<TidTracker>>,
        signals: SignalController,
        cpu_set: CpuSet,
        vfork_from: Option<Arc<Thread>>,
    ) -> Arc<Self> {
        let tid = tid.unwrap_or_else(|| Arc::new(TidTracker::new()));
        let inner = ThreadInner {
            trap_ctx,
            audit: token_set,
            sys_can_restart: false,
            sys_last_a0: 0,
            tid_address: TidAddress::default(),
            rusage: ResourceUsage::new(),
            vfork_from,
            exit_code: None,
        };
        let thread = Thread {
            tid,
            process,
            signals,
            event_bus: EventBus::default(),
            cpu_set: Mutex::new(cpu_set),
            inner: SyncUnsafeCell::new(inner),
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
            Signal::SIGCHLD => {
                if !self.signals.ignore_on_bus(signal) {
                    self.event_bus.recv_event(Event::CHILD_EXIT);
                }
            }
            Signal::SIGKILL => self.event_bus.recv_event(Event::KILL_THREAD),
            _ => {
                if !self.signals.ignore_on_bus(signal) {
                    self.event_bus.recv_event(Event::COMMON_SIGNAL);
                }
            }
        }
        self.signals.push(signal);
    }

    pub fn terminate(&self, exit_code: u32) {
        let mut proc_inner = self.process.inner.lock();
        proc_inner.threads.remove(&self.tid.0);
        self.inner().exit_code = Some(exit_code);
    }

    pub fn on_exit(self: Arc<Self>) {
        if let Some(tid_address) = self.inner().tid_address.clear {
            match user_transmute_w::<u32>(tid_address.0) {
                Ok(addr) => *addr.unwrap() = 0,
                Err(_) => warn!("[futex] Invalid clear tid address {:?}", tid_address),
            };
            debug!("[futex] Wake up clear tid address {:?}", tid_address);
            self.process.inner.lock().futex_queue.wake(tid_address, 1);
        }
        let exit_code = self.inner().exit_code.unwrap();
        self.process.on_thread_exit(self.tid.0, exit_code);
    }
}
