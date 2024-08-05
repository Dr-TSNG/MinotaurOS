pub mod aux;
pub mod ffi;
pub mod monitor;
pub mod thread;
pub mod token;

use alloc::collections::BTreeMap;
use alloc::ffi::CString;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;
use core::ptr::copy_nonoverlapping;
use core::sync::atomic::Ordering;
use log::{info, warn};
use tap::{Pipe, Tap};
use crate::arch::VirtAddr;
use crate::config::USER_STACK_TOP;
use crate::fs::fd::FdTable;
use crate::fs::ffi::InodeMode;
use crate::fs::file_system::MountNamespace;
use crate::fs::inode::Inode;
use crate::mm::addr_space::AddressSpace;
use crate::mm::protect::{user_slice_r, user_transmute_w};
use crate::process::aux::Aux;
use crate::process::ffi::{CloneFlags, CpuSet};
use crate::process::monitor::MONITORS;
use crate::process::thread::event_bus::Event;
use crate::process::thread::resource::ResourceUsage;
use crate::process::thread::{Thread, TokenSet};
use crate::process::thread::tid::TidTracker;
use crate::process::token::AccessToken;
use crate::processor::{current_process, current_thread, current_trap_ctx, SYSTEM_SHUTDOWN};
use crate::processor::hart::local_hart;
use crate::result::{Errno, SyscallResult};
use crate::sched::ffi::ITimerVal;
use crate::sched::{IdleFuture, spawn_user_thread, suspend_now};
use crate::signal::ffi::Signal;
use crate::signal::SignalController;
use crate::sync::futex::FutexQueue;
use crate::sync::mutex::{IrqReMutex, Mutex};
use crate::trap::context::TrapContext;

pub type Pid = i32;
pub type Uid = u16;
pub type Gid = u16;

pub struct Process {
    /// 进程的 pid
    pub pid: Arc<TidTracker>,
    /// 可变数据
    pub inner: IrqReMutex<ProcessInner>,
}

pub struct ProcessInner {
    /// 父进程
    pub parent: Weak<Process>,
    /// 子进程
    pub children: Vec<Arc<Process>>,
    /// 进程组
    pub pgid: Arc<TidTracker>,
    /// 进程的线程组
    pub threads: BTreeMap<Pid, Weak<Thread>>,
    /// 地址空间
    pub addr_space: Arc<Mutex<AddressSpace>>,
    /// 挂载命名空间
    pub mnt_ns: Arc<MountNamespace>,
    /// 文件描述符表
    pub fd_table: FdTable,
    /// 互斥锁队列
    pub futex_queue: FutexQueue,
    /// 定时器
    pub timers: [ITimerVal; 3],
    /// 工作目录
    pub cwd: String,
    /// 可执行文件路径
    pub exe: String,
    /// 文件创建权限掩码
    pub umask: InodeMode,
    /// 退出状态
    pub exit_code: Option<u32>,
}

impl Process {
    pub async fn new_initproc(
        mnt_ns: Arc<MountNamespace>,
        elf_data: &[u8],
    ) -> SyscallResult<Arc<Self>> {
        let (addr_space, entry, _) =
            AddressSpace::from_elf(&mnt_ns, elf_data, AccessToken::root()).await?;
        let pid = Arc::new(TidTracker::new());

        let process = Arc::new(Process {
            pid: pid.clone(),
            inner: IrqReMutex::new(ProcessInner {
                parent: Weak::new(),
                children: Vec::new(),
                pgid: pid.clone(),
                threads: BTreeMap::new(),
                addr_space: Arc::new(Mutex::new(addr_space)),
                mnt_ns,
                fd_table: FdTable::new(),
                futex_queue: Default::default(),
                timers: Default::default(),
                cwd: String::from("/"),
                exe: String::from("/init"),
                umask: InodeMode::S_IWGRP | InodeMode::S_IWOTH,
                exit_code: None,
            }),
        });

        let trap_ctx = TrapContext::new(entry, USER_STACK_TOP.0);
        let thread = Thread::new(
            process.clone(),
            trap_ctx,
            TokenSet::default(),
            Some(pid.clone()),
            SignalController::new(),
            CpuSet::new(1),
            None,
        );
        process.inner.lock().threads.insert(pid.0, Arc::downgrade(&thread));

        let mut monitors = MONITORS.lock();
        monitors.process.add(pid.0, Arc::downgrade(&process));
        monitors.group.create_group(pid.0);
        spawn_user_thread(thread);
        info!("Init process created, pid: {}", pid.0);
        Ok(process.clone())
    }

    pub async fn execve(
        &self,
        inode: Arc<dyn Inode>,
        args: &[CString],
        envs: &[CString],
        token: AccessToken,
    ) -> SyscallResult<usize> {
        let mnt_ns = self.inner.lock().mnt_ns.clone();
        let (addr_space, entry, mut auxv) =
            AddressSpace::from_inode(&mnt_ns, inode.clone(), token).await?;

        current_process().inner.lock().pipe_ref_mut(|proc_inner| {
            if proc_inner.threads.len() > 1 {
                warn!("[execve] More than one thread in process when execve");
            }

            // 终止除了当前线程外的所有线程
            let current_tid = current_thread().tid.0;
            proc_inner.threads
                .extract_if(|tid, _| *tid != current_tid)
                .for_each(|(_, thread)| {
                    if let Some(thread) = thread.upgrade() {
                        thread.terminate(0);
                    }
                });

            // 切换页表，复制文件描述符表
            unsafe { local_hart().switch_page_table(addr_space.token, addr_space.root_pt); }
            let task = local_hart().ctx.user_task.as_mut().unwrap();
            task.token = addr_space.token;
            task.root_pt = addr_space.root_pt;
            proc_inner.addr_space = Arc::new(Mutex::new(addr_space));
            proc_inner.fd_table.cloexec();
            proc_inner.timers = Default::default();
            proc_inner.exe = inode.mnt_ns_path(&proc_inner.mnt_ns)?;
            Ok(())
        })?;

        let mut user_sp = USER_STACK_TOP.0;

        // 写入参数和环境变量
        fn write_args(args: &[CString], sp: &mut usize) -> SyscallResult<Vec<usize>> {
            let mut store = vec![0; args.len()];
            for (i, arg) in args.iter().enumerate() {
                let arg_bytes = arg.as_bytes_with_nul();
                *sp -= arg_bytes.len();
                store[i] = *sp;
                unsafe {
                    copy_nonoverlapping(arg_bytes.as_ptr(), *sp as *mut u8, arg_bytes.len());
                }
            }
            *sp -= *sp % size_of::<usize>();
            Ok(store)
        }
        let envp = write_args(envs, &mut user_sp)?;
        let argv = write_args(args, &mut user_sp)?;
        auxv.push(Aux::new(aux::AT_EXECFN, argv[0]));

        // 写入 `platform`
        let platform = CString::new("RISC-V64").unwrap();
        let platform_bytes = platform.as_bytes_with_nul();
        user_sp -= platform_bytes.len();
        auxv.push(Aux::new(aux::AT_PLATFORM, user_sp));
        unsafe {
            copy_nonoverlapping(platform_bytes.as_ptr(), user_sp as *mut u8, platform_bytes.len());
        }

        // 写入 16 字节随机数（这里直接写入 0）
        user_sp -= 16;
        auxv.push(Aux::new(aux::AT_RANDOM, user_sp));
        auxv.push(Aux::new(aux::AT_NULL, 0));
        user_sp -= user_sp % 16;

        // 写入向量表
        fn write_vector<T>(vec: Vec<T>, add_zero: bool, sp: &mut usize) {
            *sp -= vec.len() * size_of::<T>();
            if add_zero {
                *sp -= size_of::<T>();
            }
            let base = *sp;
            for (i, val) in vec.into_iter().enumerate() {
                unsafe {
                    let ptr = (base as *mut T).add(i);
                    ptr.write(val);
                }
            }
        }
        write_vector(auxv, false, &mut user_sp);
        write_vector(envp, true, &mut user_sp);
        write_vector(argv, true, &mut user_sp);

        // 写入 `argc`
        user_sp -= size_of::<usize>();
        unsafe {
            let ptr = user_sp as *mut usize;
            *ptr = args.len();
        }

        // 重置线程状态
        let thread = current_thread();
        thread.signals.reset();
        thread.inner().tap_mut(|it| {
            it.trap_ctx = TrapContext::new(entry, user_sp);
            it.tid_address = Default::default();
            it.rusage = ResourceUsage::new();
            if let Some(parent) = it.vfork_from.take() {
                parent.event_bus.recv_event(Event::VFORK_DONE);
            }
        });

        info!(
            "[execve] Execve process (pid: {}): args {:?}, env {:?}",
            current_process().pid.0, args, envs,
        );
        Ok(0)
    }

    pub async fn fork_process(self: &Arc<Self>, flags: CloneFlags, stack: usize) -> SyscallResult<Pid> {
        let mut monitors = MONITORS.lock();
        let new_pid = Arc::new(TidTracker::new());
        let is_vfork = flags.contains(CloneFlags::CLONE_VFORK);
        let (new_thread, pgid) = self.inner.lock().pipe_ref_mut(|proc_inner| {
            let addr_space = if is_vfork {
                proc_inner.addr_space.clone()
            } else {
                Arc::new(Mutex::new(proc_inner.addr_space.lock().fork()))
            };
            let new_process = Arc::new(Process {
                pid: new_pid.clone(),
                inner: IrqReMutex::new(ProcessInner {
                    parent: Arc::downgrade(self),
                    children: Vec::new(),
                    pgid: proc_inner.pgid.clone(),
                    threads: BTreeMap::new(),
                    addr_space,
                    mnt_ns: proc_inner.mnt_ns.clone(),
                    fd_table: proc_inner.fd_table.clone(),
                    futex_queue: Default::default(),
                    timers: Default::default(),
                    cwd: proc_inner.cwd.clone(),
                    exe: proc_inner.exe.clone(),
                    umask: proc_inner.umask,
                    exit_code: None,
                }),
            });
            // 地址空间 fork 后需要刷新 TLB
            unsafe { local_hart().refresh_tlb(proc_inner.addr_space.lock().token); }

            let mut trap_ctx = current_trap_ctx().clone();
            trap_ctx.user_x[10] = 0;
            if stack != 0 {
                trap_ctx.set_sp(stack);
            }
            let signals = if flags.contains(CloneFlags::CLONE_SIGHAND) {
                current_thread().signals.clone_shared()
            } else {
                current_thread().signals.clone_private()
            };
            let new_cpu_set = current_thread().cpu_set.lock().clone();
            let vfork_from = is_vfork.then(|| current_thread().clone());
            let new_thread = Thread::new(
                new_process.clone(),
                trap_ctx,
                current_thread().inner().token_set.clone(),
                Some(new_pid.clone()),
                signals,
                new_cpu_set,
                vfork_from,
            );
            new_process.inner.lock().threads.insert(new_pid.0, Arc::downgrade(&new_thread));
            proc_inner.children.push(new_process.clone());

            (new_thread, proc_inner.pgid.0)
        });

        monitors.process.add(new_pid.0, Arc::downgrade(&new_thread.process));
        monitors.thread.add(new_thread.tid.0, Arc::downgrade(&new_thread));
        monitors.group.add_process(pgid, new_pid.0);
        spawn_user_thread(new_thread);
        info!(
            "[fork_process] New process (pid = {}) created, flags {:?}",
            new_pid.0, flags,
        );
        if flags.contains(CloneFlags::CLONE_VFORK) {
            let _ = suspend_now(None, Event::VFORK_DONE, IdleFuture).await;
        }
        Ok(new_pid.0)
    }

    pub fn clone_thread(
        self: &Arc<Self>,
        flags: CloneFlags,
        stack: usize,
        tls: usize,
        ptid: usize,
        ctid: usize,
    ) -> SyscallResult<Pid> {
        let new_thread = self.inner.lock().pipe_ref_mut(|proc_inner| {
            user_slice_r(stack, size_of::<usize>() * 2)?;
            let entry = unsafe {
                *(stack as *const usize)
            };
            let args_addr = unsafe {
                let ptr = stack + size_of::<usize>();
                *(ptr as *const usize)
            };
            let mut trap_ctx = current_trap_ctx().clone();
            trap_ctx.set_pc(entry);
            trap_ctx.set_sp(stack);
            trap_ctx.user_x[10] = args_addr;
            trap_ctx.user_x[4] = tls;
            let signals = if flags.contains(CloneFlags::CLONE_SIGHAND) {
                current_thread().signals.clone_shared()
            } else {
                current_thread().signals.clone_private()
            };

            let new_cpu_set = current_thread().cpu_set.lock().clone();
            let new_thread = Thread::new(
                self.clone(),
                trap_ctx,
                current_thread().inner().token_set.clone(),
                None,
                signals,
                new_cpu_set,
                None,
            );
            let new_tid = new_thread.tid.0;
            proc_inner.threads.insert(new_tid, Arc::downgrade(&new_thread));

            if flags.contains(CloneFlags::CLONE_PARENT_SETTID) {
                let ptid = user_transmute_w(ptid)?.ok_or(Errno::EINVAL)?;
                *ptid = new_tid;
            }
            if flags.contains(CloneFlags::CLONE_CHILD_CLEARTID) {
                user_transmute_w::<Pid>(ctid)?.ok_or(Errno::EINVAL)?;
                new_thread.inner().tid_address.clear = Some(VirtAddr(ctid));
            }
            if flags.contains(CloneFlags::CLONE_CHILD_SETTID) {
                user_transmute_w::<Pid>(ctid)?.ok_or(Errno::EINVAL)?;
                new_thread.inner().tid_address.set = Some(VirtAddr(ctid));
            }

            Ok(new_thread)
        })?;
        let new_tid = new_thread.tid.0;

        MONITORS.lock().thread.add(new_tid, Arc::downgrade(&new_thread));
        spawn_user_thread(new_thread);
        info!(
            "[clone_thread] New thread (tid = {}) created, flags {:?}, ptid {:#x}, ctid {:#x}",
            new_tid, flags, ptid, ctid,
        );
        Ok(new_tid)
    }

    pub fn terminate(&self, exit_code: u32) {
        let mut proc_inner = self.inner.lock();
        proc_inner.exit_code = Some(exit_code);
        proc_inner.threads.retain(|_, thread| {
            if let Some(thread) = thread.upgrade() {
                thread.inner().exit_code = Some(exit_code);
            }
            false
        });
    }

    pub fn on_thread_exit(&self, tid: Pid, exit_code: u32) {
        info!("Thread {} exited with code {}", tid, exit_code);
        let monitor = MONITORS.lock();
        let mut proc_inner = self.inner.lock();
        proc_inner.threads.remove(&tid);
        // 如果没有线程了，通知父进程
        if proc_inner.threads.is_empty() {
            proc_inner.exit_code = Some(exit_code);
            if let Some(parent) = proc_inner.parent.upgrade() {
                parent.on_child_exit(self.pid.0, exit_code);
            }
            // 将子进程的父进程设置为 init
            proc_inner.children.iter_mut().for_each(|child| {
                child.inner.lock().parent = monitor.process.init_proc();
            })
        }
    }

    fn on_child_exit(&self, pid: Pid, exit_code: u32) {
        info!("Child {} exited with code {}", pid, exit_code);
        for thread in self.inner.lock().threads.values() {
            if let Some(thread) = thread.upgrade() {
                thread.recv_signal(Signal::SIGCHLD);
                break;
            }
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.pid.0 == 1 {
            SYSTEM_SHUTDOWN.store(true, Ordering::Relaxed);
        }
    }
}
