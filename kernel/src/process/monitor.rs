use alloc::collections::BTreeMap;
use alloc::sync::Weak;
use crate::process::{Pid, Process, Tid};
use crate::process::thread::Thread;
use crate::sync::mutex::IrqMutex;

pub static PROCESS_MONITOR: ProcessMonitor = IrqMutex::new(ProcessMonitorInner(BTreeMap::new()));
pub static THREAD_MONITOR: ThreadMonitor = IrqMutex::new(ThreadMonitorInner(BTreeMap::new()));

pub type ProcessMonitor = IrqMutex<ProcessMonitorInner>;
pub type ThreadMonitor = IrqMutex<ThreadMonitorInner>;

pub struct ProcessMonitorInner(BTreeMap<Pid, Weak<Process>>);
pub struct ThreadMonitorInner(BTreeMap<Tid, Weak<Thread>>);

impl ProcessMonitorInner {
    pub fn add(&mut self, pid: Pid, process: Weak<Process>) {
        self.0.insert(pid, process);
    }

    pub fn remove(&mut self, pid: Pid) {
        self.0.remove(&pid);
    }

    pub fn count(&self) -> usize {
        self.0.values().fold(0, |acc, p| {
            if p.strong_count() > 0 { acc + 1 } else { acc }
        })
    }

    pub fn get(&self, pid: Pid) -> Weak<Process> {
        self.0.get(&pid).cloned().unwrap_or(Weak::new())
    }

    pub fn init_proc(&self) -> Weak<Process> {
        self.get(1)
    }
}

impl ThreadMonitorInner {
    pub fn add(&mut self, tid: Tid, thread: Weak<Thread>) {
        self.0.insert(tid, thread);
    }

    pub fn remove(&mut self, tid: Tid) {
        self.0.remove(&tid);
    }

    pub fn get(&self, tid: Tid) -> Weak<Thread> {
        self.0.get(&tid).cloned().unwrap_or(Weak::new())
    }
}
