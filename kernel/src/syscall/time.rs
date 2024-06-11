use core::mem::size_of;
use core::pin::pin;
use core::time::Duration;

use zerocopy::{AsBytes, FromBytes};

use crate::arch::VirtAddr;
use crate::process::thread::event_bus::Event;
use crate::processor::{current_process, current_thread};
use crate::result::{Errno, SyscallResult};
use crate::sched::ffi::{TimeSpec, CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID, TMS};
use crate::sched::sleep_for;
use crate::sched::time::{current_time, GLOBAL_CLOCK};

pub async fn sys_nanosleep(req: usize, _rem: usize) -> SyscallResult<usize> {
    let user_buf = current_process()
        .inner
        .lock()
        .addr_space
        .user_slice_r(VirtAddr(req), size_of::<TimeSpec>())?;
    let ts = TimeSpec::ref_from(user_buf).unwrap();
    let duration = Duration::from(*ts);
    current_thread()
        .event_bus
        .suspend_with(Event::all(), pin!(sleep_for(duration)))
        .await?;
    Ok(0)
}

pub fn sys_clock_gettime(clock_id: usize, buf: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let user_buf = proc_inner
        .addr_space
        .user_slice_w(VirtAddr(buf), size_of::<TimeSpec>())?;
    match clock_id {
        CLOCK_PROCESS_CPUTIME_ID => {
            let mut time = Duration::ZERO;
            for thread in proc_inner.threads.values() {
                if let Some(thread) = thread.upgrade() {
                    let rusage = &thread.inner().rusage;
                    time += rusage.user_time + rusage.sys_time;
                }
            }
            user_buf.copy_from_slice(TimeSpec::from(time).as_bytes());
        }
        CLOCK_THREAD_CPUTIME_ID => {
            let rusage = &current_thread().inner().rusage;
            let time = TimeSpec::from(rusage.user_time + rusage.sys_time);
            user_buf.copy_from_slice(time.as_bytes());
        }
        _ => {
            if let Some(clock_time) = GLOBAL_CLOCK.get(clock_id) {
                let time = TimeSpec::from(clock_time + current_time());
                user_buf.copy_from_slice(time.as_bytes());
            } else {
                return Err(Errno::EINVAL);
            }
        }
    }
    Ok(0)
}

pub fn sys_times(buf: usize) -> SyscallResult<usize> {
    let user_buf = current_process()
        .inner
        .lock()
        .addr_space
        .user_slice_w(VirtAddr(buf), size_of::<TMS>())?;
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
    let user_tv = proc_inner
        .addr_space
        .user_slice_w(VirtAddr(tv), size_of::<TimeSpec>())?;
    user_tv.copy_from_slice(time.as_bytes());
    Ok(0)
}
