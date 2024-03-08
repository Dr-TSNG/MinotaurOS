pub mod aux;
pub mod thread;
pub mod monitor;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use log::info;
use crate::fs::fd::FdTable;
use crate::fs::file_system::MountNamespace;
use crate::mm::addr_space::AddressSpace;
use crate::mm::page_table::PageTable;
use crate::process::monitor::PROCESS_MONITOR;
use crate::process::thread::Thread;
use crate::process::thread::tid::TidTracker;
use crate::result::MosResult;
use crate::sched::spawn_user_thread;
use crate::sync::mutex::IrqMutex;
use crate::trap::context::TrapContext;

type Tid = usize;
type Pid = usize;
type Gid = usize;

pub struct Process {
    /// 进程的 pid
    pub pid: Arc<TidTracker>,
    /// 进程的根页表
    pub root_pt: PageTable,
    /// 可变数据
    pub inner: IrqMutex<ProcessInner>,
}

pub struct ProcessInner {
    /// 父进程
    pub parent: Weak<Process>,
    /// 子进程
    pub children: Vec<Arc<Process>>,
    /// 进程组
    pub pgid: Gid,
    /// 进程的线程组
    pub threads: BTreeMap<Tid, Weak<Thread>>,
    /// 地址空间
    pub addr_space: AddressSpace,
    /// 挂载命名空间
    pub mnt_ns: Arc<MountNamespace>,
    /// 文件描述符表
    pub fd_table: FdTable,
    /// 工作目录
    pub cwd: String,
    /// 是否终止
    pub terminated: bool,
}

impl Process {
    pub fn new_initproc(mnt_ns: Arc<MountNamespace>, elf_data: &[u8]) -> MosResult<Arc<Self>> {
        let (addr_space, entry_point, ustack_top, auxv) = AddressSpace::from_elf(elf_data)?;
        let pid = Arc::new(TidTracker::new());
        let inner = ProcessInner {
            parent: Weak::new(),
            children: Vec::new(),
            pgid: pid.0,
            threads: BTreeMap::new(),
            addr_space,
            mnt_ns,
            fd_table: FdTable::new(),
            cwd: String::from("/"),
            terminated: false,
        };
        let process = Process {
            pid: pid.clone(),
            root_pt: inner.addr_space.root_pt,
            inner: IrqMutex::new(inner),
        };
        let process = Arc::new(process);
        let trap_ctx = TrapContext::new(entry_point, ustack_top);
        let thread = Thread::new(process.clone(), trap_ctx, Some(pid.clone()));
        process.inner.lock().apply_mut(|inner| {
            inner.parent = Arc::downgrade(&process);
            inner.threads.insert(pid.0, Arc::downgrade(&thread));
        });
        PROCESS_MONITOR.add(pid.0, Arc::downgrade(&process));
        spawn_user_thread(thread);
        info!("Init process created, pid: {}", pid.0);
        Ok(process.clone())
    }
}
