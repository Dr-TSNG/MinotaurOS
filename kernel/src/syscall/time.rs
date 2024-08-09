use alloc::sync::Arc;
use core::pin::pin;
use core::time::Duration;
use log::{debug, warn};
use macros::suspend;
use crate::mm::protect::{user_transmute_r, user_transmute_w};
use crate::process::thread::event_bus::Event;
use crate::processor::{current_process, current_thread};
use crate::result::{Errno, SyscallResult};
use crate::sched::ffi::{CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID, ITimerType, ITimerVal, TIMER_ABSTIME, TimeSpec, TimeVal, TimeZone, TMS};
use crate::sched::{sleep_for, spawn_kernel_thread, suspend_now};
use crate::sched::time::{cpu_time, GLOBAL_CLOCK, real_time};
use crate::sched::timer::TimerFuture;
use crate::signal::ffi::Signal;

#[suspend]
pub async fn sys_nanosleep(req: usize, _rem: usize) -> SyscallResult<usize> {
    let req = user_transmute_r::<TimeSpec>(req)?.ok_or(Errno::EINVAL)?;
    let duration = Duration::from(*req);
    sleep_for(duration).await?;
    Ok(0)
}

pub fn sys_setitimer(which: i32, new_value: usize, old_value: usize) -> SyscallResult<usize> {
    let which = ITimerType::try_from(which).map_err(|_| Errno::EINVAL)?;
    let now = cpu_time();
    let new_value = user_transmute_r::<ITimerVal>(new_value)?.ok_or(Errno::EINVAL)?;
    let interval = Duration::from(new_value.interval);
    let next_int = Duration::from(new_value.value);
    let next_exp = next_int + now;
    debug!("[setitimer] which: {:?}, interval: {:?}, next: {:?}", which, interval, next_int);

    let mut proc_inner = current_process().inner.lock();
    if old_value != 0 {
        let timer = proc_inner.timers[which as usize].clone();
        let rest_time = Duration::from(timer.value).checked_sub(now).unwrap_or_default();
        *user_transmute_w::<ITimerVal>(old_value)?.ok_or(Errno::EINVAL)? = ITimerVal {
            interval: timer.interval,
            value: rest_time.into(),
        }
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
            if next_int.is_zero() {
                proc_inner.timers[which as usize] = ITimerVal::default();
            } else {
                proc_inner.timers[which as usize] = ITimerVal {
                    interval: new_value.interval,
                    value: next_exp.into(),
                };
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
    let writeback = user_transmute_w::<TimeSpec>(buf)?.ok_or(Errno::EINVAL)?;
    match clock_id {
        CLOCK_PROCESS_CPUTIME_ID => {
            let mut time = Duration::ZERO;
            for thread in current_process().inner.lock().threads.values() {
                if let Some(thread) = thread.upgrade() {
                    let rusage = &thread.inner().rusage;
                    time += rusage.user_time + rusage.sys_time;
                }
            }
            *writeback = time.into();
        }
        CLOCK_THREAD_CPUTIME_ID => {
            let rusage = &current_thread().inner().rusage;
            let time = TimeSpec::from(rusage.user_time + rusage.sys_time);
            *writeback = time;
        }
        _ => {
            if let Some(clock_time) = GLOBAL_CLOCK.get(clock_id) {
                let time = TimeSpec::from(clock_time + cpu_time());
                *writeback = time;
            } else {
                return Err(Errno::EINVAL);
            }
        }
    }
    Ok(0)
}

pub fn sys_clock_getres(clock_id: usize, buf: usize) -> SyscallResult<usize> {
    let writeback = user_transmute_w::<TimeSpec>(buf)?.ok_or(Errno::EINVAL)?;
    if matches!(clock_id, CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID) || GLOBAL_CLOCK.get(clock_id).is_some() {
        *writeback = Duration::from_micros(1).into();
        Ok(0)
    } else {
        Err(Errno::EINVAL)
    }
}

pub async fn sys_clock_nanosleep(clock_id: usize, flags: i32, rqtp: usize, remain: usize) -> SyscallResult<usize> {
    let rqtp = *user_transmute_r::<TimeSpec>(rqtp)?.ok_or(Errno::EFAULT)?;
    let clock_time = GLOBAL_CLOCK.get(clock_id).ok_or(Errno::EFAULT)?;
    let now = cpu_time();
    let sleep_time = if flags & TIMER_ABSTIME != 0 {
        Duration::from(rqtp).checked_sub(now + clock_time).unwrap_or_default()
    } else {
        Duration::from(rqtp)
    };
    let ret = suspend_now(None, Event::all(), pin!(sleep_for(sleep_time))).await;
    match ret {
        Ok(()) => Ok(0),
        Err(e) => {
            if remain != 0 && flags & TIMER_ABSTIME == 0 {
                let rest = sleep_time.checked_sub(cpu_time() - now).unwrap_or_default();
                *user_transmute_w::<TimeSpec>(remain)?.ok_or(Errno::EFAULT)? = rest.into();
            }
            Err(e)
        }
    }
}

pub fn sys_times(buf: usize) -> SyscallResult<usize> {
    let now = real_time();
    let rusage = &current_thread().inner().rusage;
    let tms = TMS {
        tms_utime: rusage.user_time.as_secs(),
        tms_stime: rusage.sys_time.as_secs(),
        // TODO: cutime and cstime are not implemented
        tms_cutime: 0,
        tms_cstime: 0,
    };
    *user_transmute_w(buf)?.ok_or(Errno::EINVAL)? = tms;
    Ok(now.as_secs() as usize)
}

pub fn sys_gettimeofday(tv: usize, tz: usize) -> SyscallResult<usize> {
    let tv = user_transmute_w::<TimeVal>(tv)?.ok_or(Errno::EFAULT)?;
    let tz = user_transmute_w(tz)?;
    *tv = real_time().into();
    if let Some(tz) = tz {
        *tz = TimeZone::default();
    }
    Ok(0)
}
