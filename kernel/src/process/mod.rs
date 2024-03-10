pub mod aux;
pub mod thread;
pub mod monitor;
pub mod ffi;

use alloc::collections::BTreeMap;
use alloc::ffi::CString;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;
use core::ptr::copy_nonoverlapping;
use log::{info, warn};
use crate::arch::VirtAddr;
use crate::fs::fd::FdTable;
use crate::fs::file_system::MountNamespace;
use crate::mm::addr_space::AddressSpace;
use crate::process::aux::Aux;
use crate::process::ffi::CloneFlags;
use crate::process::monitor::PROCESS_MONITOR;
use crate::process::thread::Thread;
use crate::process::thread::tid::TidTracker;
use crate::processor::{current_process, current_thread, current_trap_ctx};
use crate::processor::hart::local_hart;
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
    pub async fn new_initproc(mnt_ns: Arc<MountNamespace>, elf_data: &[u8]) -> MosResult<Arc<Self>> {
        let (addr_space, entry, user_sp, _) =
            AddressSpace::from_elf(&mnt_ns, elf_data).await?;
        let pid = Arc::new(TidTracker::new());

        let process = Arc::new(Process {
            pid: pid.clone(),
            inner: IrqMutex::new(ProcessInner {
                parent: Weak::new(),
                children: Vec::new(),
                pgid: pid.0,
                threads: BTreeMap::new(),
                addr_space,
                mnt_ns,
                fd_table: FdTable::new(),
                cwd: String::from("/"),
                terminated: false,
            }),
        });

        let trap_ctx = TrapContext::new(entry, user_sp);
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

    pub async fn execve(
        &self,
        elf_data: &[u8],
        args: &[CString],
        envs: &[CString],
    ) -> SyscallResult<()> {
        let mnt_ns = self.inner.lock().mnt_ns.clone();
        let (addr_space, entry, mut user_sp, mut auxv) =
            AddressSpace::from_elf(&mnt_ns, elf_data).await.unwrap();

        current_process().inner.lock().apply_mut(|proc_inner| {
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
            unsafe { addr_space.activate(); }
            let hart = local_hart();
            hart.ctx.user_task.as_mut().unwrap().root_pt = addr_space.root_pt;
            proc_inner.addr_space = addr_space;
            proc_inner.fd_table.cloexec();
        });

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

        // 写入 `platform`
        let platform = CString::new("RISC-V64").unwrap();
        let platform_bytes = platform.as_bytes_with_nul();
        user_sp -= platform_bytes.len();
        unsafe {
            copy_nonoverlapping(platform_bytes.as_ptr(), user_sp as *mut u8, platform_bytes.len());
        }

        // 写入 16 字节随机数（这里直接写入 0）
        user_sp -= 16;
        auxv.push(Aux::new(aux::AT_RANDOM, user_sp));
        user_sp -= user_sp % 16;

        auxv.push(Aux::new(aux::AT_EXECFN, argv[0]));   // 文件名
        auxv.push(Aux::new(aux::AT_NULL, 0));           // 结束标志

        // 写入向量表
        fn write_vector<T>(vec: Vec<T>, add_zero: bool, sp: &mut usize) -> usize {
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
            base
        }
        let auxv_base = write_vector(auxv, false, &mut user_sp);
        let envp_base = write_vector(envp, true, &mut user_sp);
        let argv_base = write_vector(argv, true, &mut user_sp);

        // 写入 `argc`
        user_sp -= size_of::<usize>();
        unsafe {
            let ptr = user_sp as *mut usize;
            *ptr = args.len();
        }

        // a0 -> argc, a1 -> argv, a2 -> envp, a3 -> auxv
        let trap_ctx = current_trap_ctx();
        *trap_ctx = TrapContext::new(entry, user_sp);
        trap_ctx.user_x[10] = args.len();
        trap_ctx.user_x[11] = argv_base;
        trap_ctx.user_x[12] = envp_base;
        trap_ctx.user_x[13] = auxv_base;

        info!(
            "[execve] Execve process (pid: {}): argc {:#x}, argv {:#x}, envp {:#x}, auxv {:#x}, sp {:#x}",
            current_process().pid.0, args.len(), argv_base, envp_base, auxv_base, user_sp,
        );
        Ok(())
    }

    pub fn fork_process(self: &Arc<Self>, flags: CloneFlags, stack: usize) -> SyscallResult<Pid> {
        let new_pid = Arc::new(TidTracker::new());

        let new_thread = self.inner.lock().apply_mut(|proc_inner| {
            let new_process = Arc::new(Process {
                pid: new_pid.clone(),
                inner: IrqMutex::new(ProcessInner {
                    parent: Arc::downgrade(self),
                    children: Vec::new(),
                    pgid: new_pid.0,
                    threads: BTreeMap::new(),
                    addr_space: proc_inner.addr_space.fork().unwrap(),
                    mnt_ns: proc_inner.mnt_ns.clone(),
                    fd_table: proc_inner.fd_table.clone(),
                    cwd: proc_inner.cwd.clone(),
                    terminated: false,
                }),
            });

            let mut trap_ctx = current_trap_ctx().clone();
            if stack != 0 {
                trap_ctx.set_sp(stack);
            }
            let new_thread = Thread::new(new_process.clone(), trap_ctx, Some(new_pid.clone()));
            proc_inner.threads.insert(new_pid.0, Arc::downgrade(&new_thread));

            new_thread
        });

        PROCESS_MONITOR.add(new_pid.0, Arc::downgrade(&new_thread.process));
        spawn_user_thread(new_thread);
        info!(
            "[fork_process] New process (pid = {}) created from parent process (pid = {}, tid = {})",
            new_pid.0, self.pid.0, current_thread().tid.0,
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
        let new_thread = self.inner.lock().apply_mut(|proc_inner| {
            proc_inner.addr_space.user_slice_r(VirtAddr(stack), size_of::<usize>() * 2)?;
            let entry = unsafe {
                *(stack as *const usize)
            };
            let args_addr = unsafe {
                let ptr = stack + size_of::<usize>();
                *(ptr as *const usize)
            };
            let mut trap_ctx = current_trap_ctx().clone();
            trap_ctx.sepc = entry;
            trap_ctx.set_sp(stack);
            trap_ctx.user_x[10] = args_addr;
            trap_ctx.user_x[4] = tls;

            let new_thread = Thread::new(self.clone(), trap_ctx, None);
            let new_tid = new_thread.tid.0;
            proc_inner.threads.insert(new_tid, Arc::downgrade(&new_thread));

            if flags.contains(CloneFlags::CLONE_PARENT_SETTID) {
                let buf = proc_inner.addr_space.user_slice_w(VirtAddr(ptid), size_of::<usize>())?;
                buf.copy_from_slice(&new_tid.to_ne_bytes());
            }
            if flags.contains(CloneFlags::CLONE_CHILD_CLEARTID) {
                proc_inner.addr_space.user_slice_w(VirtAddr(ctid), size_of::<usize>())?;
                new_thread.inner().tid_address.clear_tid_address = Some(ctid);
            }
            if flags.contains(CloneFlags::CLONE_CHILD_SETTID) {
                let buf = proc_inner.addr_space.user_slice_w(VirtAddr(ctid), size_of::<usize>())?;
                buf.copy_from_slice(&new_tid.to_ne_bytes());
                new_thread.inner().tid_address.set_tid_address = Some(ctid);
            }

            Ok(new_thread)
        })?;
        let new_tid = new_thread.tid.0;

        spawn_user_thread(new_thread);
        info!(
            "[clone_thread] New thread (tid = {}) for process (pid = {}) created",
            new_tid, self.pid.0,
        );
        Ok(new_tid)
    }
}
