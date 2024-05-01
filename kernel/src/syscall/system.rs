use alloc::vec;
use log::{debug, info};
use zerocopy::AsBytes;
use crate::arch::{shutdown, VirtAddr};
use crate::debug::console::DMESG;
use crate::debug::ffi::SyslogCmd;
use crate::fs::ffi::UTS_NAME;
use crate::processor::current_process;
use crate::result::{Errno, SyscallResult};

pub fn sys_shutdown() -> ! {
    info!("Shutdown command from user space");
    shutdown()
}

pub fn sys_syslog(cmd: i32, buf: usize, len: usize) -> SyscallResult<usize> {
    let cmd = SyslogCmd::try_from(cmd).map_err(|_| Errno::EINVAL)?;
    debug!("[syslog] cmd: {:?}, buf: {:#x}, len: {}", cmd, buf, len);
    match cmd {
        SyslogCmd::SYSLOG_ACTION_READ_ALL => {
            let mut lines = vec![];
            DMESG.lock().apply(|dmesg| {
                let mut size = 0;
                for line in dmesg.buf.iter().rev() {
                    if size + line.len() > len {
                        break;
                    }
                    lines.push(line.clone());
                    size += line.len();
                }
            });

            let buf = current_process().inner.lock().addr_space.user_slice_w(VirtAddr(buf), len)?;
            let mut size = 0;
            for line in lines {
                buf[size..size + line.len()].copy_from_slice(line.as_bytes());
                size += line.len();
            }
            Ok(size)
        }
        _ => Err(Errno::EINVAL),
    }
}

pub fn sys_uname(buf: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let user_buf = proc_inner.addr_space
        .user_slice_w(VirtAddr(buf), UTS_NAME.as_bytes().len())?;
    user_buf.copy_from_slice(UTS_NAME.as_bytes());
    Ok(0)
}
