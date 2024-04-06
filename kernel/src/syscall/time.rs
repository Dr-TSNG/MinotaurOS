use core::mem::size_of;
use core::pin::pin;
use core::time::Duration;
use futures::future::{Either, select};
use zerocopy::{AsBytes, FromBytes};
use crate::arch::VirtAddr;
use crate::process::thread::wait::Event;
use crate::processor::{current_process, current_thread};
use crate::result::{Errno, SyscallResult};
use crate::sched::ffi::{TimeSpec, TMS};
use crate::sched::sleep_for;
use crate::sched::time::current_time;

pub async fn sys_nanosleep(req: usize, _rem: usize) -> SyscallResult<usize> {
    let user_buf = current_process().inner.lock().addr_space.user_slice_r(VirtAddr(req), size_of::<TimeSpec>())?;
    let ts = TimeSpec::ref_from(user_buf).unwrap();
    let duration = Duration::from(*ts);
    match select(
        pin!(sleep_for(duration)),
        pin!(current_thread().event_bus.wait(Event::all())),
    ).await {
        Either::Left((_, _)) => Ok(0),
        Either::Right(_) => Err(Errno::EINTR),
    }
}

pub fn sys_times(buf: usize) -> SyscallResult<usize> {
    let user_buf = current_process().inner.lock().addr_space.user_slice_w(VirtAddr(buf), size_of::<TMS>())?;
    let now = current_time();
    let rusage = &current_thread().inner().rusage;
    let tms = TMS {
        tms_utime: rusage.user_time.as_secs(),
        tms_stime: rusage.sys_time.as_secs(),
        // TODO: cutime and cstime are not implemented
        tms_cutime: 0,
        tms_cstime: 0,
    };
    user_buf.copy_from_slice(tms.as_bytes());
    Ok(now.as_secs() as usize)
}

pub fn sys_gettimeofday(tv: usize, _tz: usize) -> SyscallResult<usize> {
    let time = TimeSpec::from(current_time());
    let proc_inner = current_process().inner.lock();
    let user_tv = proc_inner.addr_space.user_slice_w(VirtAddr(tv), size_of::<TimeSpec>())?;
    user_tv.copy_from_slice(time.as_bytes());
    Ok(0)
}
