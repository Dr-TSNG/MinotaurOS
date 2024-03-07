use crate::arch::VirtAddr;
use crate::fs::ffi::TimeSpec;
use crate::processor::current_process;
use crate::result::SyscallResult;
use crate::sched::time::current_time;

pub fn sys_gettimeofday(tv: usize, _tz: usize) -> SyscallResult<usize> {
    let time = TimeSpec::from(current_time());
    let mut proc_inner = current_process().inner.lock();
    let user_tv = proc_inner.addr_space
        .user_slice_w(VirtAddr(tv), core::mem::size_of::<TimeSpec>())?;
    user_tv.copy_from_slice(time.as_bytes());
    Ok(0)
}
