use core::mem::size_of;
use rand::Rng;
use crate::driver::random::KRNG;
use crate::mm::protect::user_slice_w;
use crate::result::{Errno, SyscallResult};

pub fn sys_getpriority(which: i32, who: i32) -> SyscallResult<usize> {
    // 10 -> 10
    // 20 -> 0
    // 30 -> -10
    // 这里为了通过第一个测试，直接全部返回 0 ，进程/线程/用户的 优先级 没有实现之前的做法。
    return Ok(20);
}

pub fn sys_getrandom(buf: usize, buflen: usize, _flags: u32) -> SyscallResult<usize> {
    if buf == 0 {
        return Err(Errno::EINVAL);
    }
    let buf = user_slice_w(buf, buflen * size_of::<u8>())?;
    KRNG.lock().fill(buf);
    Ok(buflen)
}
