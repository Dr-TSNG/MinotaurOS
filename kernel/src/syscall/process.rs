use crate::processor::current_thread;
use crate::result::SyscallResult;
use crate::sched::yield_now;

pub fn sys_exit(exit_code: i8) -> SyscallResult<isize> {
    current_thread().terminate(exit_code);
    Ok(0)
}

pub async fn sys_yield() -> SyscallResult<isize> {
    yield_now().await;
    Ok(0)
}

