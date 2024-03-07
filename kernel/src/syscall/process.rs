use crate::processor::{current_process, current_thread};
use crate::result::SyscallResult;
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
