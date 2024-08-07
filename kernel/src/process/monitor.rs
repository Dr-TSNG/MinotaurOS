use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::cell::RefCell;
use crate::process::{Pid, Process};
use crate::process::thread::Thread;
use crate::result::{Errno, SyscallResult};
use crate::sync::mutex::ReMutex;

pub static MONITORS: ReMutex<Monitors> = ReMutex::new(Monitors::new());

pub struct Monitors {
    pub thread: ThreadMonitor,
    pub process: ProcessMonitor,
    pub group: ProcessGroupMonitor,
}

pub struct ThreadMonitor(BTreeMap<Pid, Weak<Thread>>);
pub struct ProcessMonitor(BTreeMap<Pid, Weak<Process>>);
pub struct ProcessGroupMonitor(BTreeMap<Pid, RefCell<BTreeSet<Pid>>>);

impl Monitors {
    const fn new() -> Self {
        Self {
            thread: ThreadMonitor(BTreeMap::new()),
            process: ProcessMonitor(BTreeMap::new()),
            group: ProcessGroupMonitor(BTreeMap::new()),
        }
    }
}

impl ThreadMonitor {
    pub fn add(&mut self, tid: Pid, thread: Weak<Thread>) {
        self.0.insert(tid, thread);
    }

    pub fn remove(&mut self, tid: Pid) {
        self.0.remove(&tid);
    }

    pub fn get(&self, tid: Pid) -> Weak<Thread> {
        self.0.get(&tid).cloned().unwrap_or(Weak::new())
    }
}

impl ProcessMonitor {
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

    pub fn all(&self) -> Vec<Arc<Process>> {
        self.0.values().filter_map(|p| p.upgrade()).collect()
    }

    pub fn get(&self, pid: Pid) -> Weak<Process> {
        self.0.get(&pid).cloned().unwrap_or(Weak::new())
    }

    pub fn init_proc(&self) -> Weak<Process> {
        self.get(1)
    }
}

impl ProcessGroupMonitor {
    pub fn create_group(&mut self, pid: Pid) {
        let mut set = BTreeSet::new();
        set.insert(pid);
        self.0.insert(pid, RefCell::new(set));
    }

    pub fn remove_group(&mut self, pgid: Pid) {
        self.0.remove(&pgid);
    }

    pub fn add_process(&mut self, pgid: Pid, pid: Pid) {
        let group = self.0.get(&pgid).unwrap();
        group.borrow_mut().insert(pid);
    }

    pub fn move_to_group(&mut self, old_pgid: Pid, pid: Pid, new_pgid: Pid) -> SyscallResult {
        let old_group = self.0.get(&old_pgid).ok_or(Errno::ESRCH)?;
        let new_group = self.0.get(&new_pgid).ok_or(Errno::EPERM)?;
        old_group.borrow_mut().remove(&pid);
        new_group.borrow_mut().insert(pid);
        Ok(())
    }

    pub fn get_group(&self, pgid: Pid) -> Option<Vec<Pid>> {
        self.0.get(&pgid).map(|group| group.borrow_mut().iter().cloned().collect())
    }
}
