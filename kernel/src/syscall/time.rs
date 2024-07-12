use alloc::sync::Arc;
use core::mem::size_of;
use core::pin::pin;
use core::time::Duration;
use log::{debug, warn};
use zerocopy::{AsBytes, FromBytes};

use crate::arch::VirtAddr;
use crate::process::thread::event_bus::Event;
use crate::processor::{current_process, current_thread};
use crate::result::{Errno, SyscallResult};
use crate::sched::ffi::{CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID, ITimerType, ITimerVal, TIMER_ABSTIME, TimeSpec, TimeVal, TMS};
use crate::sched::{sleep_for, spawn_kernel_thread};
use crate::sched::time::{cpu_time, GLOBAL_CLOCK, real_time};
use crate::sched::timer::TimerFuture;
use crate::signal::ffi::Signal;

pub async fn sys_nanosleep(req: usize, _rem: usize) -> SyscallResult<usize> {
    let user_buf = current_process().inner.lock().addr_space.user_slice_r(VirtAddr(req), size_of::<TimeSpec>())?;
    let ts = TimeSpec::ref_from(user_buf).unwrap();
    let duration = Duration::from(*ts);
    current_thread().event_bus.suspend_with(Event::all(), pin!(sleep_for(duration))).await?;
    Ok(0)
}

pub fn sys_setitimer(which: i32, new_value: usize, old_value: usize) -> SyscallResult<usize> {
    let which = ITimerType::try_from(which).map_err(|_| Errno::EINVAL)?;
    let mut proc_inner = current_process().inner.lock();
    let now = cpu_time();
    let new_value = proc_inner.addr_space.user_slice_r(VirtAddr(new_value), size_of::<ITimerVal>())?;
    let new_value = ITimerVal::ref_from(new_value).unwrap();
    let interval = Duration::from(new_value.interval);
    let next_int = Duration::from(new_value.value);
    let next_exp = next_int + now;
    debug!("[setitimer] which: {:?}, interval: {:?}, next: {:?}", which, interval, next_int);

    if old_value != 0 {
        let old_value = proc_inner.addr_space.user_slice_w(VirtAddr(old_value), size_of::<TimeVal>())?;
        let rest_time = Duration::from(proc_inner.timers[which as usize].value)
            .checked_sub(now).unwrap_or_default();
        old_value.copy_from_slice(TimeVal::from(rest_time).as_bytes());
    }

    match which {
        ITimerType::Real => {
            let proc = Arc::downgrade(current_process());
            let callback = move || {
                if let Some(proc) = proc.upgrade() {
                    let proc_inner = &mut *proc.inner.lock();
                    let timer = &mut proc_inner.timers[which as usize];
                    let single_shot = Duration::from(timer.interval).is_zero();
                    let disarmed = Duration::from(timer.value).is_zero();
                    if !disarmed {
                        for thread in proc_inner.threads.values() {
                            if let Some(thread) = thread.upgrade() {
                                thread.recv_signal(Signal::SIGALRM);
                                break;
                            }
                        }
                        if !single_shot {
                            let next_exp = Duration::from(timer.interval) + cpu_time();
                            timer.value = next_exp.into();
                            return next_exp;
                        }
                    }
                }
                Duration::ZERO
            };
            proc_inner.timers[which as usize] = ITimerVal {
                interval: new_value.interval,
                value: next_exp.into(),
            };
            if next_int != now {
                spawn_kernel_thread(TimerFuture::new(next_exp, callback));
            }
        }
        _ => {
            warn!("[setitimer] unsupported timer type: {:?}", which);
            return Err(Errno::EINVAL);
        }
    }
    Ok(0)
}

pub fn sys_clock_gettime(clock_id: usize, buf: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let user_buf = proc_inner.addr_space.user_slice_w(VirtAddr(buf), size_of::<TimeSpec>())?;
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
                let time = TimeSpec::from(clock_time + cpu_time());
                user_buf.copy_from_slice(time.as_bytes());
            } else {
                return Err(Errno::EINVAL);
            }
        }
    }
    Ok(0)
}

pub fn sys_clock_getres(clock_id: usize, buf: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let user_buf = proc_inner.addr_space.user_slice_w(VirtAddr(buf), size_of::<TimeSpec>())?;
    if matches!(clock_id, CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID) || GLOBAL_CLOCK.get(clock_id).is_some() {
        let time = TimeSpec::from(Duration::from_nanos(1));
        user_buf.copy_from_slice(time.as_bytes());
        Ok(0)
    } else {
        Err(Errno::EINVAL)
    }
}

pub async fn sys_clock_nanosleep(clock_id: usize, flags: i32, rqtp: usize, remain: usize) -> SyscallResult<usize> {
    let rqtp = current_process().inner.lock()
        .addr_space.user_slice_r(VirtAddr(rqtp), size_of::<TimeSpec>())?;
    let rqtp = *TimeSpec::ref_from(rqtp).unwrap();
    let clock_time = GLOBAL_CLOCK.get(clock_id).ok_or(Errno::EINVAL)?;
    let now = cpu_time();
    let sleep_time = if flags & TIMER_ABSTIME != 0 {
        clock_time + Duration::from(rqtp)
    } else {
        clock_time + now + Duration::from(rqtp)
    };
    current_thread().event_bus.suspend_with(Event::all(), pin!(sleep_for(sleep_time))).await?;
    if remain != 0 {
        let remain = current_process().inner.lock()
            .addr_space.user_slice_w(VirtAddr(remain), size_of::<TimeSpec>())?;
        let rest = sleep_time.checked_sub(cpu_time() - now).unwrap_or_default();
        remain.copy_from_slice(TimeSpec::from(rest).as_bytes());
    }
    Ok(0)
}

pub fn sys_times(buf: usize) -> SyscallResult<usize> {
    let user_buf = current_process().inner.lock().addr_space.user_slice_w(VirtAddr(buf), size_of::<TMS>())?;
    let now = real_time();
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
    let time = TimeSpec::from(real_time());
    let proc_inner = current_process().inner.lock();
    let user_tv = proc_inner.addr_space.user_slice_w(VirtAddr(tv), size_of::<TimeSpec>())?;
    user_tv.copy_from_slice(time.as_bytes());
    Ok(0)
}
