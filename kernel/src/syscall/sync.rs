use core::mem::size_of;
use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use log::debug;
use num_enum::TryFromPrimitive;
use tap::Tap;
use crate::arch::VirtAddr;
use crate::mm::protect::{user_slice_r, user_transmute_r};
use crate::process::thread::event_bus::Event;
use crate::processor::current_process;
use crate::result::{Errno, SyscallResult};
use crate::sched::ffi::TimeSpec;
use crate::sched::suspend_now;
use crate::sync::ffi::FutexOp;
use crate::sync::futex::FutexFuture;

pub async fn sys_futex(uaddr: usize, op: i32, val: u32, timeout: usize, uaddr2: usize, _val3: usize) -> SyscallResult<usize> {
    let cval = user_slice_r(uaddr, size_of::<u32>())?;
    let cval = unsafe { AtomicU32::from_ptr(cval.as_ptr().cast::<u32>().cast_mut()).load(Ordering::Relaxed) };
    let op = FutexOp::try_from_primitive(op % 128).map_err(|_| Errno::EINVAL)?;
    match op {
        FutexOp::Wait => {
            if cval == val {
                let timeout = match user_transmute_r::<TimeSpec>(timeout)? {
                    Some(timeout) => {
                        timeout.check_forward()?;
                        Some(Duration::from(*timeout))
                    },
                    None => None,
                };
                suspend_now(timeout, Event::all(), FutexFuture::new(VirtAddr(uaddr), val)).await
                    .tap_mut(|it| {
                    if matches!(it, Err(Errno::ETIMEDOUT)) {
                        debug!("[futex] timeout");
                    }
                })?;
            } else {
                return Err(Errno::EAGAIN);
            }
        }
        FutexOp::Wake => {
            let cnt = current_process().inner.lock()
                .futex_queue.wake(VirtAddr(uaddr), val as usize);
            return Ok(cnt);
        }
        FutexOp::Requeue | FutexOp::CmpRequeue => {
            let val2 = timeout;
            user_slice_r(uaddr2, size_of::<u32>())?;
            let cnt = current_process().inner.lock()
                .futex_queue.requeue(VirtAddr(uaddr), VirtAddr(uaddr2), val as usize, val2);
            return Ok(cnt);
        }
        _ => {}
    }
    Ok(0)
}
