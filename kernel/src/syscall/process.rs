use log::debug;
use crate::process::ffi::CloneFlags;
use crate::processor::{current_process, current_thread};
use crate::result::{Errno, SyscallResult};
use crate::sched::yield_now;

pub fn sys_exit(exit_code: i8) -> SyscallResult<usize> {
    current_thread().terminate(exit_code);
    Ok(0)
}

pub async fn sys_yield() -> SyscallResult<usize> {
    yield_now().await;
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

pub fn sys_getuid() -> SyscallResult<usize> {
    // TODO: Real UID support
    Ok(0)
}

pub fn sys_geteuid() -> SyscallResult<usize> {
    // TODO: Real UID support
    Ok(0)
}

pub fn sys_getegid() -> SyscallResult<usize> {
    // TODO: Real UID support
    Ok(0)
}

pub fn sys_gettid() -> SyscallResult<usize> {
    Ok(current_thread().tid.0)
}

pub fn sys_clone(
    flags: u32,
    stack: usize,
    ptid: usize,
    tls: usize,
    ctid: usize,
) -> SyscallResult<usize> {
    let flags = CloneFlags::from_bits(flags).ok_or(Errno::EINVAL)?;
    debug!("[sys_clone] flags: {:?}", flags);
    if flags.contains(CloneFlags::CLONE_VM) {
        current_process().clone_thread(flags, stack, tls, ptid, ctid)
    } else {
        current_process().fork_process(flags, stack)
    }
}
