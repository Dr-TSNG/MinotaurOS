use alloc::ffi::CString;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;
use core::time::Duration;
use log::{debug, info, warn};
use crate::arch::VirtAddr;
use crate::config::USER_STACK_SIZE;
use crate::fs::ffi::{AT_FDCWD, InodeMode, PATH_MAX};
use crate::fs::path::resolve_path;
use crate::mm::protect::{user_transmute_r, user_transmute_str, user_transmute_w};
use crate::process::ffi::{CloneFlags, CpuSet, Rlimit, RlimitCmd, RUsage, RUSAGE_SELF, RUSAGE_THREAD, WaitOptions};
use crate::process::{Gid, Pid, Tid};
use crate::process::monitor::MONITORS;
use crate::process::thread::event_bus::{Event, WaitPidFuture};
use crate::processor::{current_process, current_thread};
use crate::result::{Errno, SyscallResult};
use crate::sched::{suspend_now, yield_now};
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
    Ok(current_thread().tid.0 as usize)
}

pub fn sys_sched_setaffinity(tid: Tid, cpusetsize: usize, mask: usize) -> SyscallResult<usize> {
    if cpusetsize != size_of::<CpuSet>() {
        return Err(Errno::EINVAL);
    }
    let mask = user_transmute_r::<CpuSet>(mask)?.ok_or(Errno::EINVAL)?;
    let thread = match tid {
        0 => current_thread().clone(),
        _ => MONITORS.lock().thread.get(tid).upgrade().ok_or(Errno::ESRCH)?,
    };
    *thread.cpu_set.lock() = *mask;
    Ok(0)
}

pub fn sys_sched_getaffinity(tid: Tid, cpusetsize: usize, mask: usize) -> SyscallResult<usize> {
    if cpusetsize != size_of::<CpuSet>() {
        return Err(Errno::EINVAL);
    }
    let mask = user_transmute_w::<CpuSet>(mask)?.ok_or(Errno::EINVAL)?;
    let thread = match tid {
        0 => current_thread().clone(),
        _ => MONITORS.lock().thread.get(tid).upgrade().ok_or(Errno::ESRCH)?,
    };
    *mask = thread.cpu_set.lock().clone();
    Ok(0)
}

pub async fn sys_sched_yield() -> SyscallResult<usize> {
    yield_now().await;
    Ok(0)
}

pub fn sys_kill(pid: Pid, signal: usize) -> SyscallResult<usize> {
    let signal = Signal::try_from(signal).map_err(|_| Errno::EINVAL)?;
    let monitors = MONITORS.lock();
    let procs = match pid {
        0 => {
            let pgid = current_process().inner.lock().pgid.0;
            monitors.group.get_group(pgid).unwrap()
        }
        _ => vec![pid],
    };
    let mut handled = false;
    for pid in procs {
        if let Some(process) = monitors.process.get(pid).upgrade() {
            handled = true;
            if signal != Signal::None {
                for thread in process.inner.lock().threads.values() {
                    if let Some(thread) = thread.upgrade() {
                        thread.recv_signal(signal);
                        break;
                    }
                }
            }
        }
    }
    handled.then_some(0).ok_or(Errno::EINVAL)
}

pub fn sys_tkill(tid: Tid, signal: usize) -> SyscallResult<usize> {
    let signal = Signal::try_from(signal).map_err(|_| Errno::EINVAL)?;
    if let Some(thread) = MONITORS.lock().thread.get(tid).upgrade() {
        thread.recv_signal(signal);
        return Ok(0);
    }
    Err(Errno::EINVAL)
}

pub fn sys_setpgid(pid: Pid, pgid: Gid) -> SyscallResult<usize> {
    let mut monitors = MONITORS.lock();
    let proc = match pid {
        0 => current_process().clone(),
        _ => monitors.process.get(pid).upgrade().ok_or(Errno::ESRCH)?,
    };
    let new_pgid = match pgid {
        0 => proc.inner.lock().pgid.0,
        _ => pgid,
    };

    let mut proc_inner = proc.inner.lock();
    let delegate = monitors.process.get(new_pgid).upgrade().ok_or(Errno::EPERM)?;
    monitors.group.move_to_group(proc_inner.pgid.0, proc.pid.0, new_pgid)?;
    proc_inner.pgid = delegate.pid.clone();
    Ok(0)
}

pub fn sys_getpgid(pid: Pid) -> SyscallResult<usize> {
    let proc = match pid {
        0 => current_process().clone(),
        _ => MONITORS.lock().process.get(pid).upgrade().ok_or(Errno::ESRCH)?,
    };
    let pgid = proc.inner.lock().pgid.0;
    Ok(pgid as usize)
}

pub fn sys_setsid() -> SyscallResult<usize> {
    warn!("setsid is not implemented");
    Ok(0)
}

pub fn sys_getrlimit(resource: u32, rlim: usize) -> SyscallResult<usize> {
    sys_prlimit(current_process().pid.0, resource, 0, rlim)
}

pub fn sys_setrlimit(resource: u32, rlim: usize) -> SyscallResult<usize> {
    sys_prlimit(current_process().pid.0, resource, rlim, 0)
}

pub fn sys_getrusage(who: i32, buf: usize) -> SyscallResult<usize> {
    let writeback = user_transmute_w(buf)?.ok_or(Errno::EINVAL)?;
    let rusage = match who {
        RUSAGE_SELF => {
            let mut utime = Duration::ZERO;
            let mut stime = Duration::ZERO;
            for thread in current_process().inner.lock().threads.values() {
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
    *writeback = rusage;
    Ok(0)
}

pub fn sys_getpid() -> SyscallResult<usize> {
    Ok(current_process().pid.0 as usize)
}

pub fn sys_getppid() -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    // SAFETY: 由于我们将 init 进程的 parent 设置为自己，所以这里可以直接 unwrap
    Ok(proc_inner.parent.upgrade().unwrap().pid.0 as usize)
}

pub fn sys_gettid() -> SyscallResult<usize> {
    Ok(current_thread().tid.0 as usize)
}

pub fn sys_clone(flags: u32, stack: usize, ptid: usize, tls: usize, ctid: usize) -> SyscallResult<usize> {
    let flags = CloneFlags::from_bits(flags).ok_or(Errno::EINVAL)?;
    let ret = if flags.contains(CloneFlags::CLONE_VM) {
        current_process().clone_thread(flags, stack, tls, ptid, ctid)
    } else {
        current_process().fork_process(flags, stack)
    };
    ret.map(|tid| tid as usize)
}

pub async fn sys_execve(path: usize, args: usize, envs: usize) -> SyscallResult<usize> {
    let mut path = user_transmute_str(path, PATH_MAX)?.ok_or(Errno::EINVAL)?;
    let mut args_vec: Vec<CString> = Vec::new();
    let mut envs_vec: Vec<CString> = Vec::new();
    if path.ends_with(".sh") {
        path = "/busybox";
        args_vec.push(CString::new("busybox").unwrap());
        args_vec.push(CString::new("sh").unwrap());
    }
    let push_args = |args_vec: &mut Vec<CString>, mut arg_ptr: usize| -> SyscallResult {
        loop {
            let arg_addr = user_transmute_r::<usize>(arg_ptr)?.ok_or(Errno::EINVAL)?;
            let arg = match user_transmute_str(*arg_addr, PATH_MAX)? {
                None => break,
                Some(s) if s.is_empty() => break,
                Some(s) => s,
            };
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
        envs_vec.push(CString::new("LD_LIBRARY_PATH=/:/lib:/lib/glibc:/lib/musl").unwrap());
    }

    let inode = resolve_path(AT_FDCWD, path, true).await?;
    if inode.metadata().mode == InodeMode::IFDIR {
        return Err(Errno::EISDIR);
    }

    current_process().execve(inode, &args_vec, &envs_vec).await
}

pub async fn sys_wait4(pid: Pid, wstatus: usize, options: u32, _rusage: usize) -> SyscallResult<usize> {
    let options = WaitOptions::from_bits(options).ok_or(Errno::EINVAL)?;
    info!("[wait4] pid: {:?}, wstatus: {:#x}, options: {:?}", pid as isize, wstatus, options);
    current_thread().signals.set_waiting_child(true);
    let fut = WaitPidFuture::new(pid, options, wstatus);
    let ret = suspend_now(None, Event::all().difference(Event::CHILD_EXIT), fut).await;
    current_thread().signals.set_waiting_child(false);
    info!("[wait4] ret: {:?}", ret);
    ret.map(|pid| pid as usize)
}

pub fn sys_prlimit(pid: Pid, resource: u32, new_rlim: usize, old_rlim: usize) -> SyscallResult<usize> {
    let cmd = RlimitCmd::try_from(resource).map_err(|_| Errno::EINVAL)?;
    let mut proc_inner = current_process().inner.lock();
    debug!("[prlimit] pid: {}, cmd: {:?}, nrlim: {}, orlim :{}", pid, cmd, new_rlim, old_rlim);
    if let Some(old_rlim) = user_transmute_w::<Rlimit>(old_rlim)? {
        let limit = match cmd {
            RlimitCmd::RLIMIT_STACK => Rlimit::new(USER_STACK_SIZE, USER_STACK_SIZE),
            RlimitCmd::RLIMIT_NOFILE => proc_inner.fd_table.rlimit.clone(),
            _ => return Ok(0),
        };
        *old_rlim = limit;
    }
    if let Some(new_rlim) = user_transmute_r::<Rlimit>(new_rlim)? {
        if new_rlim.rlim_cur > new_rlim.rlim_max {
            return Err(Errno::EINVAL);
        }
        match cmd {
            RlimitCmd::RLIMIT_NOFILE => proc_inner.fd_table.rlimit = new_rlim.clone(),
            _ => return Ok(0),
        };
    }
    Ok(0)
}
