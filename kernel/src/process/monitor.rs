use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use crate::process::{Pid, Process};
use crate::sync::mutex::IrqMutex;

pub static PROCESS_MONITOR: ProcessMonitor = ProcessMonitor::new();

pub struct ProcessMonitor(IrqMutex<BTreeMap<Pid, Weak<Process>>>);

impl ProcessMonitor {
    pub const fn new() -> Self {
        Self(IrqMutex::new(BTreeMap::new()))
    }

    pub fn add(&self, pid: Pid, process: Weak<Process>) {
        self.0.lock().insert(pid, process);
    }

    pub fn remove(&self, pid: Pid) {
        self.0.lock().remove(&pid);
    }

    pub fn get(&self, pid: Pid) -> Option<Arc<Process>> {
        self.0.lock().get(&pid).and_then(|p| p.upgrade())
    }
    
    pub fn init_proc(&self) -> Arc<Process> {
        self.get(1).unwrap()
    }
}
