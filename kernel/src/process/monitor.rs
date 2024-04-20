use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use crate::process::{Pid, Process};
use crate::sync::mutex::IrqMutex;

pub static PROCESS_MONITOR: ProcessMonitor = IrqMutex::new(ProcessMonitorInner(BTreeMap::new()));

pub type ProcessMonitor = IrqMutex<ProcessMonitorInner>;

pub struct ProcessMonitorInner(BTreeMap<Pid, Weak<Process>>);

impl ProcessMonitorInner {
    pub fn add(&mut self, pid: Pid, process: Weak<Process>) {
        self.0.insert(pid, process);
    }

    pub fn remove(&mut self, pid: Pid) {
        self.0.remove(&pid);
    }

    pub fn get(&self, pid: Pid) -> Option<Arc<Process>> {
        self.0.get(&pid).and_then(|p| p.upgrade())
    }

    pub fn init_proc(&self) -> Arc<Process> {
        self.get(1).unwrap()
    }
}
