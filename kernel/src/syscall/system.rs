use alloc::vec;
use core::mem::size_of;
use log::{debug, info};
use zerocopy::AsBytes;
use crate::arch::{shutdown, VirtAddr};
use crate::debug::console::DMESG;
use crate::driver::total_memory;
use crate::fs::ffi::UTS_NAME;
use crate::mm::allocator::free_user_memory;
use crate::process::monitor::PROCESS_MONITOR;
use crate::processor::current_process;
use crate::result::{Errno, SyscallResult};
use crate::sched::time::current_time;
use crate::syscall::system::ffi::{SysInfo, SyslogCmd};

mod ffi {
    use num_enum::TryFromPrimitive;
    use zerocopy::AsBytes;

    #[allow(non_camel_case_types)]
    #[derive(Debug, TryFromPrimitive)]
    #[repr(i32)]
    pub enum SyslogCmd {
        SYSLOG_ACTION_CLOSE = 0,
        SYSLOG_ACTION_OPEN = 1,
        SYSLOG_ACTION_READ = 2,
        SYSLOG_ACTION_READ_ALL = 3,
        SYSLOG_ACTION_READ_CLEAR = 4,
        SYSLOG_ACTION_CLEAR = 5,
        SYSLOG_ACTION_CONSOLE_OFF = 6,
        SYSLOG_ACTION_CONSOLE_ON = 7,
        SYSLOG_ACTION_CONSOLE_LEVEL = 8,
        SYSLOG_ACTION_SIZE_UNREAD = 9,
        SYSLOG_ACTION_SIZE_BUFFER = 10,
    }

    #[derive(Default, AsBytes)]
    #[repr(C)]
    pub struct SysInfo {
        /// Seconds since boot
        pub uptime: isize,
        /// 1, 5, and 15 minute load averages
        pub loads: [usize; 3],
        /// Total usable main memory size
        pub totalram: usize,
        /// Available memory size
        pub freeram: usize,
        /// Amount of shared memory
        pub sharedram: usize,
        /// Memory used by buffers
        pub bufferram: usize,
        /// Total swap space size
        pub totalswap: usize,
        /// swap space still available
        pub freeswap: usize,
        /// Number of current processes
        pub procs: u16,
        /// Padding
        __pad1: [u8; 6],
        /// Total high memory size
        pub totalhigh: usize,
        /// Available high memory size
        pub freehigh: usize,
        /// Memory unit size in bytes
        pub mem_uint: u32,
        /// Padding
        pub __pad2: [u8; 4],
    }
}

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

pub fn sys_sysinfo(buf: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let user_buf = proc_inner.addr_space.user_slice_w(VirtAddr(buf), size_of::<SysInfo>())?;
    let mut sys_info = SysInfo::default();
    sys_info.uptime = current_time().as_secs() as isize;
    sys_info.totalram = total_memory();
    sys_info.freeram = free_user_memory();
    sys_info.procs = PROCESS_MONITOR.lock().count() as u16;
    user_buf.copy_from_slice(sys_info.as_bytes());
    Ok(0)
}
