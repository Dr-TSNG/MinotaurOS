use log::info;
use crate::arch::{shutdown, VirtAddr};
use crate::fs::ffi::UTS_NAME;
use crate::processor::current_process;
use crate::result::SyscallResult;

pub fn sys_shutdown() -> ! {
    info!("Shutdown command from user space");
    shutdown()
}

pub fn sys_uname(buf: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let user_buf = proc_inner.addr_space
        .user_slice_w(VirtAddr(buf), UTS_NAME.as_bytes().len())?;
    user_buf.copy_from_slice(UTS_NAME.as_bytes());
    Ok(0)
}
