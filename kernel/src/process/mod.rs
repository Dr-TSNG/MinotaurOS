pub mod aux;
pub mod thread;
pub mod monitor;
pub mod ffi;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::mem::size_of;
use log::info;
use crate::arch::VirtAddr;
use crate::fs::fd::FdTable;
use crate::fs::file_system::MountNamespace;
use crate::mm::addr_space::AddressSpace;
use crate::mm::page_table::PageTable;
use crate::process::ffi::CloneFlags;
use crate::process::monitor::PROCESS_MONITOR;
use crate::process::thread::Thread;
use crate::process::thread::tid::TidTracker;
use crate::processor::{current_thread, current_trap_ctx};
use crate::result::{MosResult, SyscallResult};
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
        let process = Arc::new(Process {
            pid: pid.clone(),
            root_pt: inner.addr_space.root_pt,
            inner: IrqMutex::new(inner),
        });

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

    pub fn fork_process(
        self: &Arc<Self>,
        flags: CloneFlags,
        stack: usize,
    ) -> SyscallResult<Pid> {
        let new_pid = Arc::new(TidTracker::new());

        let new_inner = self.inner.lock().apply_mut(|proc_inner| {
            ProcessInner {
                parent: Arc::downgrade(self),
                children: Vec::new(),
                pgid: new_pid.0,
                threads: BTreeMap::new(),
                addr_space: proc_inner.addr_space.fork().unwrap(),
                mnt_ns: proc_inner.mnt_ns.clone(),
                fd_table: proc_inner.fd_table.clone(),
                cwd: proc_inner.cwd.clone(),
                terminated: false,
            }
        });
        let new_process = Arc::new(Process {
            pid: new_pid.clone(),
            root_pt: new_inner.addr_space.root_pt,
            inner: IrqMutex::new(new_inner),
        });

        let mut trap_ctx = current_trap_ctx().clone();
        if stack != 0 {
            trap_ctx.set_sp(stack);
        }
        let new_thread = Thread::new(new_process.clone(), trap_ctx, Some(new_pid.clone()));
        new_process.inner.lock().apply_mut(|inner| {
            inner.threads.insert(new_pid.0, Arc::downgrade(&new_thread));
        });

        PROCESS_MONITOR.add(new_pid.0, Arc::downgrade(&new_process));
        spawn_user_thread(new_thread);
        info!(
            "[fork_process] New process (pid = {}) created from parent process (pid = {}, tid = {})",
            new_pid.0,
            self.pid.0,
            current_thread().tid.0,
        );
        Ok(new_pid.0)
    }

    pub fn clone_thread(
        self: &Arc<Self>,
        flags: CloneFlags,
        stack: usize,
        tls: usize,
        ptid: usize,
        ctid: usize,
    ) -> SyscallResult<Tid> {
        let mut proc_inner = self.inner.lock();
        proc_inner.addr_space.user_slice_r(VirtAddr(stack), size_of::<usize>() * 2)?;
        let entry_point = unsafe {
            *(stack as *const usize)
        };
        let args_addr = unsafe {
            let ptr = stack + size_of::<usize>();
            *(ptr as *const usize)
        };
        let mut trap_ctx = current_trap_ctx().clone();
        trap_ctx.sepc = entry_point;
        trap_ctx.set_sp(stack);
        trap_ctx.user_x[10] = args_addr;
        trap_ctx.user_x[4] = tls;

        let new_thread = Thread::new(self.clone(), trap_ctx, None);
        let new_tid = new_thread.tid.0;
        proc_inner.threads.insert(new_tid, Arc::downgrade(&new_thread));

        if flags.contains(CloneFlags::CLONE_PARENT_SETTID) {
            proc_inner.addr_space.user_slice_w(VirtAddr(ptid), size_of::<usize>())?;
            unsafe {
                *(ptid as *mut usize) = new_thread.tid.0;
            }
        }
        // TODO: CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID

        spawn_user_thread(new_thread);
        info!(
            "[clone_thread] New thread (tid = {}) for process (pid = {}) created",
            new_tid,
            self.pid.0
        );

        Ok(new_tid)
    }
}
