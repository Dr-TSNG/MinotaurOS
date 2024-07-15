use alloc::ffi::CString;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::mem::size_of;
use core::time::Duration;
use log::{debug, info, warn};
use zerocopy::{AsBytes, FromBytes};
use crate::arch::VirtAddr;
use crate::config::{MAX_FD_NUM, USER_STACK_SIZE, USER_STACK_TOP};
use crate::fs::ffi::{AT_FDCWD, InodeMode, OpenFlags, PATH_MAX};
use crate::fs::path::resolve_path;
use crate::process::ffi::{CloneFlags, CpuSet, Rlimit, RlimitCmd, RUsage, RUSAGE_SELF, RUSAGE_THREAD, WaitOptions};
use crate::process::monitor::{PROCESS_MONITOR, THREAD_MONITOR};
use crate::process::{Pid, Tid};
use crate::process::thread::event_bus::{Event, WaitPidFuture};
use crate::processor::{current_process, current_thread};
use crate::result::{Errno, SyscallResult};
use crate::sched::yield_now;
use crate::signal::ffi::Signal;

pub fn sys_exit(exit_code: i8) -> SyscallResult<usize> {
    current_thread().terminate(exit_code);
    Ok(0)
}

pub fn sys_exit_group(exit_code: i8) -> SyscallResult<usize> {
    current_process().terminate(exit_code);
    Ok(0)
}

pub fn sys_set_tid_address(tid: usize) -> SyscallResult<usize> {
    debug!("[set_tid_address] Set clear at {:#x}", tid);
    current_thread().inner().tid_address.clear = match tid {
        0 => None,
        _ => Some(VirtAddr(tid)),
    };
    Ok(current_thread().tid.0)
}

pub fn sys_sched_setaffinity(pid: usize, cpusetsize: usize, mask: usize) -> SyscallResult<usize> {
    if cpusetsize != size_of::<CpuSet>() {
        return Err(Errno::EINVAL);
    }
    let mask = current_process().inner.lock()
        .addr_space.user_slice_r(VirtAddr(mask), size_of::<CpuSet>())?;
    let thread = match pid {
        0 => current_thread().clone(),
        _ => THREAD_MONITOR.lock().get(pid).upgrade().ok_or(Errno::ESRCH)?,
    };
    *thread.cpu_set.lock() = *CpuSet::ref_from(mask).unwrap();
    Ok(0)
}

pub fn sys_sched_getaffinity(pid: usize, cpusetsize: usize, mask: usize) -> SyscallResult<usize> {
    if cpusetsize != size_of::<CpuSet>() {
        return Err(Errno::EINVAL);
    }
    let mask = current_process().inner.lock()
        .addr_space.user_slice_w(VirtAddr(mask), size_of::<CpuSet>())?;
    let thread = match pid {
        0 => current_thread().clone(),
        _ => THREAD_MONITOR.lock().get(pid).upgrade().ok_or(Errno::ESRCH)?,
    };
    mask.copy_from_slice(thread.cpu_set.lock().as_bytes());
    Ok(0)
}

pub async fn sys_sched_yield() -> SyscallResult<usize> {
    yield_now().await;
    Ok(0)
}

pub fn sys_kill(pid: Pid, signal: usize) -> SyscallResult<usize> {
    let signal = Signal::try_from(signal).map_err(|_| Errno::EINVAL)?;
    let monitor = PROCESS_MONITOR.lock();
    if let Some(process) = monitor.get(pid).upgrade() {
        for thread in process.inner.lock().threads.values() {
            if let Some(thread) = thread.upgrade() {
                thread.recv_signal(signal);
                break;
            }
        }
        return Ok(0);
    }
    Err(Errno::EINVAL)
}

pub fn sys_tkill(tid: Tid, signal: usize) -> SyscallResult<usize> {
    let signal = Signal::try_from(signal).map_err(|_| Errno::EINVAL)?;
    let monitor = THREAD_MONITOR.lock();
    if let Some(thread) = monitor.get(tid).upgrade() {
        thread.recv_signal(signal);
        return Ok(0);
    }
    Err(Errno::EINVAL)
}

pub fn sys_getrlimit(resource: u32, rlim: usize) -> SyscallResult<usize> {
    sys_prlimit(current_process().pid.0, resource, 0, rlim)
}

pub fn sys_setrlimit(resource: u32, rlim: usize) -> SyscallResult<usize> {
    sys_prlimit(current_process().pid.0, resource, rlim, 0)
}

pub fn sys_getrusage(who: i32, buf: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let user_buf = proc_inner.addr_space.user_slice_w(VirtAddr(buf), size_of::<RUsage>())?;
    let rusage = match who {
        RUSAGE_SELF => {
            let mut utime = Duration::ZERO;
            let mut stime = Duration::ZERO;
            for thread in proc_inner.threads.values() {
                if let Some(thread) = thread.upgrade() {
                    utime += thread.inner().rusage.user_time;
                    stime += thread.inner().rusage.sys_time;
                }
            }
            RUsage {
                ru_utime: utime.into(),
                ru_stime: stime.into(),
                ..Default::default()
            }
        }
        RUSAGE_THREAD => {
            let self_r = &current_thread().inner().rusage;
            RUsage {
                ru_utime: self_r.user_time.into(),
                ru_stime: self_r.sys_time.into(),
                ..Default::default()
            }
        }
        _ => {
            warn!("[getrusage] Invalid who: {}", who);
            return Err(Errno::EINVAL);
        }
    };
    user_buf.copy_from_slice(rusage.as_bytes());
    Ok(0)
}

pub fn sys_getpid() -> SyscallResult<usize> {
    Ok(current_process().pid.0)
}

pub fn sys_getppid() -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    // SAFETY: 由于我们将 init 进程的 parent 设置为自己，所以这里可以直接 unwrap
    Ok(proc_inner.parent.upgrade().unwrap().pid.0)
}

pub fn sys_gettid() -> SyscallResult<usize> {
    Ok(current_thread().tid.0)
}

pub fn sys_clone(flags: u32, stack: usize, ptid: usize, tls: usize, ctid: usize) -> SyscallResult<usize> {
    let flags = CloneFlags::from_bits(flags).ok_or(Errno::EINVAL)?;
    if flags.contains(CloneFlags::CLONE_VM) {
        current_process().clone_thread(flags, stack, tls, ptid, ctid)
    } else {
        current_process().fork_process(flags, stack)
    }
}

pub async fn sys_execve(path: usize, args: usize, envs: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let mut path = proc_inner.addr_space.user_slice_str(VirtAddr(path), PATH_MAX)?;

    let mut args_vec: Vec<CString> = Vec::new();
    let mut envs_vec: Vec<CString> = Vec::new();
    if path.ends_with(".sh") {
        path = "/busybox";
        args_vec.push(CString::new("busybox").unwrap());
        args_vec.push(CString::new("sh").unwrap());
    }
    let push_args = |args_vec: &mut Vec<CString>, mut arg_ptr: usize| -> SyscallResult {
        loop {
            proc_inner.addr_space.user_slice_r(VirtAddr(arg_ptr), size_of::<usize>())?;
            let arg_addr = unsafe { *(arg_ptr as *const usize) };
            if arg_addr == 0 { break; }
            let arg = proc_inner.addr_space.user_slice_str(VirtAddr(arg_addr), PATH_MAX)?;
            if arg.is_empty() { break; }
            args_vec.push(CString::new(arg).unwrap());
            arg_ptr += size_of::<usize>();
        }
        Ok(())
    };
    push_args(&mut args_vec, args)?;
    push_args(&mut envs_vec, envs)?;
    if args_vec.is_empty() {
        args_vec.push(CString::new(path).unwrap());
    }
    if !envs_vec.iter().any(|s| s.to_str().unwrap().contains("PATH=")) {
        envs_vec.push(CString::new("PATH=/:/bin").unwrap());
    }
    if !envs_vec.iter().any(|s| s.to_str().unwrap().contains("LD_LIBRARY_PATH=")) {
        envs_vec.push(CString::new("LD_LIBRARY_PATH=/:/lib").unwrap());
    }

    let inode = resolve_path(&proc_inner, AT_FDCWD, path, true).await?;
    if inode.metadata().mode == InodeMode::IFDIR {
        return Err(Errno::EISDIR);
    }

    drop(proc_inner);
    let file = inode.open(OpenFlags::O_RDONLY)?;
    let elf_data = file.read_all().await?;
    current_process().execve(path.to_string(), &elf_data, &args_vec, &envs_vec).await
}

pub async fn sys_wait4(pid: Pid, wstatus: usize, options: u32, _rusage: usize) -> SyscallResult<usize> {
    let options = WaitOptions::from_bits(options).ok_or(Errno::EINVAL)?;
    info!("[wait4] pid: {:?}, wstatus: {:#x}, options: {:?}", pid as isize, wstatus, options);
    let ret = current_thread().event_bus.suspend_with(
        Event::all().difference(Event::CHILD_EXIT),
        WaitPidFuture::new(pid, options, wstatus),
    ).await;
    info!("[wait4] ret: {:?}", ret);
    ret
}

pub fn sys_prlimit(pid: Pid, resource: u32, new_rlim: usize, old_rlim: usize) -> SyscallResult<usize> {
    let cmd = RlimitCmd::try_from(resource).map_err(|_| Errno::EINVAL)?;
    let mut proc_inner = current_process().inner.lock();
    debug!("[prlimit] pid: {}, cmd: {:?}, nrlim: {}, orlim :{}", pid, cmd, new_rlim, old_rlim);
    if old_rlim != 0 {
        let old_rlim = current_process().inner.lock().addr_space
            .user_slice_w(VirtAddr(old_rlim), size_of::<Rlimit>())?;
        let orlim = unsafe { &mut *(old_rlim.as_mut_ptr() as *mut Rlimit) };
        let (cur, max) = match cmd {
            RlimitCmd::RLIMIT_STACK => (USER_STACK_SIZE, USER_STACK_TOP.0),
            RlimitCmd::RLIMIT_NOFILE => (orlim.rlim_cur, orlim.rlim_max),
            _ => (0, 0),
        };
        let limit = Rlimit { rlim_cur: cur, rlim_max: max };
        old_rlim.copy_from_slice(limit.as_bytes());
    }
    if new_rlim != 0 {
        let new_rlim = current_process().inner.lock().addr_space
            .user_slice_w(VirtAddr(new_rlim), size_of::<Rlimit>())?;
        let nrlim = unsafe { &mut *(new_rlim.as_mut_ptr() as *mut Rlimit) };
        let (cur, max) = match cmd {
            RlimitCmd::RLIMIT_NOFILE => (nrlim.rlim_cur, nrlim.rlim_max),
            _ => (MAX_FD_NUM, MAX_FD_NUM)
        };
        if cur > max {
            return Err(Errno::EINVAL);
        }
        let limit = Rlimit { rlim_cur: cur, rlim_max: max };
        proc_inner.fd_table.rlimit = limit;
    }
    Ok(0)
}
