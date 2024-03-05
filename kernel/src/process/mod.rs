pub mod aux;
pub mod thread;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use crate::fs::fd::FdTable;
use crate::mm::addr_space::AddressSpace;
use crate::process::thread::Thread;
use crate::process::thread::tid::TidTracker;
use crate::result::MosResult;
use crate::sync::mutex::IrqMutex;
use crate::trap::context::TrapContext;

type Tid = usize;
type Pid = usize;
type Gid = usize;

pub struct Process {
    /// 进程的 pid
    pid: Arc<TidTracker>,
    pub inner: IrqMutex<ProcessInner>,
}

pub struct ProcessInner {
    /// 是否僵尸进程
    pub is_zombie: bool,
    /// 父进程
    pub parent: Option<Weak<Process>>,
    /// 子进程
    pub children: Vec<Arc<Process>>,
    /// 进程的线程组
    pub threads: BTreeMap<Tid, Thread>,
    /// 地址空间
    pub addr_space: AddressSpace,
    /// 文件描述符表
    pub fd_table: FdTable,
    /// 工作目录
    pub cwd: String,
    /// 进程组
    pub pgid: Gid,
}

impl Process {
    pub fn new_initproc(elf_data: &[u8]) -> MosResult<Arc<Self>> {
        let (addr_space, entry_point, ustack_top, auxv) = AddressSpace::from_elf(elf_data)?;
        let pid = Arc::new(TidTracker::new());
        let inner = ProcessInner {
            is_zombie: false,
            parent: None,
            children: Vec::new(),
            pgid: pid.0,
            threads: BTreeMap::new(),
            addr_space,
            fd_table: FdTable::new(),
            cwd: String::from("/"),
        };
        let process = Process {
            pid: pid.clone(),
            inner: IrqMutex::new(inner),
        };
        let process = Arc::new(process);
        let trap_ctx = TrapContext::new(entry_point, ustack_top);
        let thread = Thread::new(process.clone(), trap_ctx, ustack_top, Some(pid.clone()));
        process.inner.lock().threads.insert(pid.0, thread);
        Ok(process.clone())
    }
}
