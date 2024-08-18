use alloc::ffi::CString;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;
use core::time::Duration;
use log::{debug, info, warn};
use crate::arch::VirtAddr;
use crate::config::USER_STACK_SIZE;
use crate::fs::ffi::{AccessMode, AT_FDCWD, InodeMode, PATH_MAX};
use crate::fs::path::resolve_path;
use crate::mm::protect::{user_slice_r, user_slice_w, user_transmute_r, user_transmute_str, user_transmute_w};
use crate::process::ffi::{CapSet, CapUserData, CapUserHeader, CloneFlags, CpuSet, LINUX_CAPABILITY_VERSION_1, LINUX_CAPABILITY_VERSION_2, LINUX_CAPABILITY_VERSION_3, mk_cap_user_data, mk_kernel_cap, PrctlOption, Rlimit, RlimitCmd, RUsage, RUSAGE_SELF, RUSAGE_THREAD, WaitOptions};
use crate::process::{Gid, Pid, Uid};
use crate::process::monitor::MONITORS;
use crate::process::thread::event_bus::{Event, WaitPidFuture};
use crate::processor::{current_process, current_thread};
use crate::result::{Errno, SyscallResult};
use crate::sched::{suspend_now, yield_now};
use crate::sched::ffi::SchedPolicy;
use crate::signal::ffi::Signal;

pub async fn sys_acct(filename: usize) -> SyscallResult<usize> {
    let audit = &current_thread().inner().audit;
    if audit.euid != 0 {
        return Err(Errno::EPERM);
    }
    let path = user_transmute_str(filename, PATH_MAX)?;
    match path {
        Some(path) => {
            let inode = resolve_path(AT_FDCWD, path, true, audit).await?;
            if inode.metadata().ifmt.is_dir() {
                return Err(Errno::EISDIR);
            }
            if !inode.metadata().ifmt.is_reg() {
                return Err(Errno::EACCES);
            }
            inode.audit_access(audit, AccessMode::W_OK)?;
        }
        None => (),
    }
    Ok(0)
}

pub fn sys_capget(hdrp: usize, datap: usize) -> SyscallResult<usize> {
    let header = user_transmute_r::<CapUserHeader>(hdrp)?.ok_or(Errno::EFAULT)?;
    if !matches!(header.version, LINUX_CAPABILITY_VERSION_1 | LINUX_CAPABILITY_VERSION_2 | LINUX_CAPABILITY_VERSION_3) {
        let header = user_transmute_w::<CapUserHeader>(hdrp)?.ok_or(Errno::EFAULT)?;
        header.version = LINUX_CAPABILITY_VERSION_3;
        return Err(Errno::EINVAL);
    }
    let thread = match header.pid {
        ..=-1 => return Err(Errno::EINVAL),
        0 => current_thread().clone(),
        _ => MONITORS.lock().thread.get(header.pid).upgrade().ok_or(Errno::ESRCH)?,
    };
    let data = user_transmute_w::<[CapUserData; 2]>(datap)?.ok_or(Errno::EFAULT)?;
    let (low, high) = data.split_at_mut(1);
    let caps = &mut thread.inner().audit.caps;
    mk_cap_user_data(caps.effective, &mut low[0].effective, &mut high[0].effective);
    mk_cap_user_data(caps.permitted, &mut low[0].permitted, &mut high[0].permitted);
    mk_cap_user_data(caps.inheritable, &mut low[0].inheritable, &mut high[0].inheritable);
    Ok(0)
}

pub fn sys_capset(hdrp: usize, datap: usize) -> SyscallResult<usize> {
    let header = user_transmute_r::<CapUserHeader>(hdrp)?.ok_or(Errno::EFAULT)?;
    if !matches!(header.version, LINUX_CAPABILITY_VERSION_1 | LINUX_CAPABILITY_VERSION_2 | LINUX_CAPABILITY_VERSION_3) {
        let header = user_transmute_w::<CapUserHeader>(hdrp)?.ok_or(Errno::EFAULT)?;
        header.version = LINUX_CAPABILITY_VERSION_3;
        return Err(Errno::EINVAL);
    }
    let thread = current_thread();
    if header.pid != 0 && header.pid != current_thread().tid.0 {
        return Err(Errno::EPERM);
    }
    let data = user_transmute_r::<[CapUserData; 2]>(datap)?.ok_or(Errno::EFAULT)?;
    let caps = &mut thread.inner().audit.caps;
    let effective = mk_kernel_cap(data[0].effective, data[1].effective);
    let permitted = mk_kernel_cap(data[0].permitted, data[1].permitted);
    let inheritable = mk_kernel_cap(data[0].inheritable, data[1].inheritable);

    // Attempt to add a capability to the permitted set
    if permitted - caps.permitted != CapSet::empty() {
        return Err(Errno::EPERM);
    }
    // Attempt to set a capability in the effective set that is not in the permitted set
    if effective - permitted != CapSet::empty() {
        return Err(Errno::EPERM);
    }

    if inheritable - caps.bounding != CapSet::empty() {
        return Err(Errno::EPERM);
    }
    if inheritable - permitted != CapSet::empty() && !caps.effective.contains(CapSet::CAP_SETPCAP) {
        return Err(Errno::EPERM);
    }

    if thread.tid.0 != current_thread().tid.0 && !caps.effective.contains(CapSet::CAP_SETPCAP) {
        return Err(Errno::EPERM);
    }

    caps.effective = effective;
    caps.permitted = permitted;
    caps.inheritable = inheritable;
    Ok(0)
}

pub fn sys_exit(exit_code: u32) -> SyscallResult<usize> {
    current_thread().terminate(exit_code << 8);
    Ok(0)
}

pub fn sys_exit_group(exit_code: u32) -> SyscallResult<usize> {
    current_process().terminate(exit_code << 8);
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

pub fn sys_sched_setaffinity(tid: Pid, cpusetsize: usize, mask: usize) -> SyscallResult<usize> {
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

pub fn sys_sched_getaffinity(tid: Pid, cpusetsize: usize, mask: usize) -> SyscallResult<usize> {
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

pub fn sys_sched_get_priority_max(policy: i32) -> SyscallResult<usize> {
    match SchedPolicy::try_from(policy).map_err(|_| Errno::EINVAL)? {
        SchedPolicy::SchedFifo => Ok(99),
        SchedPolicy::SchedRr => Ok(99),
        SchedPolicy::SchedOther => Ok(0),
        SchedPolicy::SchedBatch => Ok(0),
        SchedPolicy::SchedIdle => Ok(0),
        SchedPolicy::SchedDeadline => Ok(0),
    }
}

pub fn sys_sched_get_priority_min(policy: i32) -> SyscallResult<usize> {
    match SchedPolicy::try_from(policy).map_err(|_| Errno::EINVAL)? {
        SchedPolicy::SchedFifo => Ok(1),
        SchedPolicy::SchedRr => Ok(1),
        SchedPolicy::SchedOther => Ok(0),
        SchedPolicy::SchedBatch => Ok(0),
        SchedPolicy::SchedIdle => Ok(0),
        SchedPolicy::SchedDeadline => Ok(0),
    }
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

pub fn sys_tkill(tid: Pid, signal: usize) -> SyscallResult<usize> {
    let signal = Signal::try_from(signal).map_err(|_| Errno::EINVAL)?;
    if let Some(thread) = MONITORS.lock().thread.get(tid).upgrade() {
        thread.recv_signal(signal);
        return Ok(0);
    }
    Err(Errno::EINVAL)
}

pub fn sys_tgkill(tgid: Pid, tid: Pid, signal: usize) -> SyscallResult<usize> {
    let signal = Signal::try_from(signal).map_err(|_| Errno::EINVAL)?;
    let monitors = MONITORS.lock();
    let process = monitors.process.get(tgid).upgrade().ok_or(Errno::ESRCH)?;
    let thread = process.inner.lock()
        .threads.get(&tid).ok_or(Errno::ESRCH)?
        .upgrade().ok_or(Errno::ESRCH)?;
    thread.recv_signal(signal);
    Ok(0)
}

pub fn sys_setregid(rgid: Uid, egid: Uid) -> SyscallResult<usize> {
    let audit = &mut current_thread().inner().audit;
    if rgid != Uid::MAX {
        audit.rgid = rgid;
    }
    if egid != Uid::MAX {
        audit.egid = egid;
    }
    Ok(0)
}

pub fn sys_setgid(gid: Uid) -> SyscallResult<usize> {
    let audit = &mut current_thread().inner().audit;
    if audit.euid == 0 {
        audit.rgid = gid;
        audit.egid = gid;
    }
    Ok(0)
}

pub fn sys_setreuid(ruid: Uid, euid: Uid) -> SyscallResult<usize> {
    let audit = &mut current_thread().inner().audit;
    if ruid != Uid::MAX {
        audit.ruid = ruid;
    }
    if euid != Uid::MAX {
        audit.euid = euid;
    }
    Ok(0)
}

pub fn sys_setuid(uid: Uid) -> SyscallResult<usize> {
    let audit = &mut current_thread().inner().audit;
    if audit.euid == 0 {
        audit.ruid = uid;
        audit.suid = uid;
    }
    audit.euid = uid;
    Ok(0)
}

pub fn sys_setresuid(ruid: Uid, euid: Uid, suid: Uid) -> SyscallResult<usize> {
    let audit = &mut current_thread().inner().audit;
    if ruid != Uid::MAX {
        audit.ruid = ruid;
    }
    if euid != Uid::MAX {
        audit.euid = euid;
    }
    if suid != Uid::MAX {
        audit.suid = suid;
    }
    Ok(0)
}

pub fn sys_getresuid(ruid: usize, euid: usize, suid: usize) -> SyscallResult<usize> {
    let ruid = user_transmute_w::<Uid>(ruid)?.ok_or(Errno::EINVAL)?;
    let euid = user_transmute_w::<Uid>(euid)?.ok_or(Errno::EINVAL)?;
    let suid = user_transmute_w::<Uid>(suid)?.ok_or(Errno::EINVAL)?;
    let audit = &current_thread().inner().audit;
    *ruid = audit.ruid;
    *euid = audit.euid;
    *suid = audit.suid;
    Ok(0)
}

pub fn sys_setresgid(rgid: Uid, egid: Uid, sgid: Uid) -> SyscallResult<usize> {
    let audit = &mut current_thread().inner().audit;
    if rgid != Uid::MAX {
        audit.rgid = rgid;
    }
    if egid != Uid::MAX {
        audit.egid = egid;
    }
    if sgid != Uid::MAX {
        audit.sgid = sgid;
    }
    Ok(0)
}

pub fn sys_getresgid(rgid: usize, egid: usize, sgid: usize) -> SyscallResult<usize> {
    let rgid = user_transmute_w::<Uid>(rgid)?.ok_or(Errno::EINVAL)?;
    let egid = user_transmute_w::<Uid>(egid)?.ok_or(Errno::EINVAL)?;
    let sgid = user_transmute_w::<Uid>(sgid)?.ok_or(Errno::EINVAL)?;
    let audit = &current_thread().inner().audit;
    *rgid = audit.rgid;
    *egid = audit.egid;
    *sgid = audit.sgid;
    Ok(0)
}

pub fn sys_setpgid(pid: Pid, pgid: Pid) -> SyscallResult<usize> {
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

pub fn sys_getgroups(size: usize, list: usize) -> SyscallResult<usize> {
    let sup_gids = &current_thread().inner().audit.sup_gids;
    if size == 0 {
        return Ok(sup_gids.len());
    } else if size < sup_gids.len() {
        return Err(Errno::EINVAL);
    }
    let list = user_slice_w(list, size * size_of::<Gid>())?;
    let list = bytemuck::cast_slice_mut(list);
    for (i, gid) in sup_gids.iter().enumerate() {
        list[i] = *gid;
    }
    Ok(sup_gids.len())
}

pub fn sys_setgroups(size: usize, list: usize) -> SyscallResult<usize> {
    let audit = &current_thread().inner().audit;
    if audit.euid != 0 {
        return Err(Errno::EPERM);
    }
    let sup_gids = &mut current_thread().inner().audit.sup_gids;
    if size == 0 {
        sup_gids.clear();
        return Ok(0);
    } else if size > Gid::MAX as usize {
        return Err(Errno::EINVAL);
    }
    let list = user_slice_r(list, size * size_of::<Gid>())?;
    let list = bytemuck::cast_slice(list);
    sup_gids.clear();
    sup_gids.extend(list);
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

pub fn sys_umask(mask: u32) -> SyscallResult<usize> {
    let mut proc_inner = current_process().inner.lock();
    let prev = proc_inner.umask;
    proc_inner.umask = InodeMode::from_bits_access(mask);
    Ok(prev.bits() as usize)
}

pub fn sys_prctl(option: i32, arg1: usize, _arg2: usize, _arg3: usize, _arg4: usize) -> SyscallResult<usize> {
    let option = PrctlOption::try_from(option).map_err(|_| Errno::EINVAL)?;
    match option {
        PrctlOption::PR_CAPBSET_READ => {
            let cap = CapSet::from_id(arg1).ok_or(Errno::EINVAL)?;
            let caps = &current_thread().inner().audit.caps;
            Ok(caps.bounding.contains(cap) as usize)
        }
        PrctlOption::PR_CAPBSET_DROP => {
            let cap = CapSet::from_id(arg1).ok_or(Errno::EINVAL)?;
            let caps = &mut current_thread().inner().audit.caps;
            if !caps.effective.contains(CapSet::CAP_SETPCAP) {
                return Err(Errno::EPERM);
            }
            caps.bounding.remove(cap);
            Ok(0)
        }
    }
}

pub fn sys_getpid() -> SyscallResult<usize> {
    Ok(current_process().pid.0 as usize)
}

pub fn sys_getppid() -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    // SAFETY: 由于我们将 init 进程的 parent 设置为自己，所以这里可以直接 unwrap
    Ok(proc_inner.parent.upgrade().unwrap().pid.0 as usize)
}

pub fn sys_getuid() -> SyscallResult<usize> {
    Ok(current_thread().inner().audit.ruid as usize)
}

pub fn sys_geteuid() -> SyscallResult<usize> {
    Ok(current_thread().inner().audit.euid as usize)
}

pub fn sys_getgid() -> SyscallResult<usize> {
    Ok(current_thread().inner().audit.rgid as usize)
}

pub fn sys_getegid() -> SyscallResult<usize> {
    Ok(current_thread().inner().audit.egid as usize)
}

pub fn sys_gettid() -> SyscallResult<usize> {
    Ok(current_thread().tid.0 as usize)
}

pub async fn sys_clone(flags: u32, stack: usize, ptid: usize, tls: usize, ctid: usize) -> SyscallResult<usize> {
    let flags = CloneFlags::from_bits(flags).ok_or(Errno::EINVAL)?;
    let ret = if flags.contains(CloneFlags::CLONE_VM) && !flags.contains(CloneFlags::CLONE_VFORK) {
        current_process().clone_thread(flags, stack, tls, ptid, ctid)
    } else {
        current_process().fork_process(flags, stack).await
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

    let audit = &current_thread().inner().audit;
    let inode = resolve_path(AT_FDCWD, path, true, audit).await?;
    if inode.metadata().ifmt == InodeMode::S_IFDIR {
        return Err(Errno::EISDIR);
    }
    inode.audit_access(audit, AccessMode::X_OK)?;
    current_process().execve(inode, &args_vec, &envs_vec, audit).await
}

pub async fn sys_wait4(pid: Pid, wstatus: usize, options: u32, _rusage: usize) -> SyscallResult<usize> {
    let options = WaitOptions::from_bits(options).ok_or(Errno::EINVAL)?;
    info!("[wait4] pid: {:?}, wstatus: {:#x}, options: {:?}", pid as isize, wstatus, options);
    current_thread().signals.set_waiting_child(true);
    let fut = WaitPidFuture::new(pid, options, wstatus);
    let ret = suspend_now(None, Event::all().difference(Event::CHILD_EXIT), fut).await;
    current_thread().signals.set_waiting_child(false);
    if ret == Err(Errno::EINTR) {
        current_thread().inner().sys_can_restart = true;
    }
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
