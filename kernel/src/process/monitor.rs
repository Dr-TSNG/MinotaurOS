use alloc::collections::BTreeMap;
use alloc::sync::Weak;
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
