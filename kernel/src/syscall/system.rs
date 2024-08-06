use alloc::vec;
use log::{debug, info};
use tap::Tap;
use zerocopy::AsBytes;
use crate::arch::shutdown;
use crate::debug::console::DMESG;
use crate::driver::total_memory;
use crate::fs::ffi::UTS_NAME;
use crate::mm::allocator::free_user_memory;
use crate::mm::protect::{user_slice_w, user_transmute_w};
use crate::process::monitor::MONITORS;
use crate::processor::hart::local_hart;
use crate::result::{Errno, SyscallResult};
use crate::sched::time::cpu_time;
use crate::syscall::system::ffi::{SysInfo, SyslogCmd};

mod ffi {
    use num_enum::TryFromPrimitive;
    use zerocopy::{AsBytes, FromBytes, FromZeroes};

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

    #[derive(Default, AsBytes, FromZeroes, FromBytes)]
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
            DMESG.lock().tap(|dmesg| {
                let mut size = 0;
                for line in dmesg.buf.iter().rev() {
                    if size + line.len() > len {
                        break;
                    }
                    lines.push(line.clone());
                    size += line.len();
                }
            });

            let buf = user_slice_w(buf, len)?;
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
    let user_buf = user_slice_w(buf, UTS_NAME.as_bytes().len())?;
    user_buf.copy_from_slice(UTS_NAME.as_bytes());
    Ok(0)
}

pub fn sys_getcpu(cpu: usize, node: usize, _tcache: usize) -> SyscallResult<usize> {
    info!("[sys_getcpu] cpu: {}, node: {}", cpu, node);
    // 获取当前 CPU 和 NUMA 节点编号
    let (current_cpu, current_node) = (local_hart().id, 0);
    // 尝试将当前 CPU 写入用户提供的指针位置
    if cpu != 0 {
        if let Some(cpu_ptr) = user_transmute_w::<u32>(cpu)? {
            *cpu_ptr = current_cpu as u32;
        } else {
            return Err(Errno::EINVAL);
        }
    }
    // 尝试将当前 NUMA 节点写入用户提供的指针位置
    if node != 0 {
        if let Some(node_ptr) = user_transmute_w::<u32>(node)? {
            *node_ptr = current_node;
        } else {
            return Err(Errno::EINVAL);
        }
    }
    Ok(0)
}

pub fn sys_sysinfo(buf: usize) -> SyscallResult<usize> {
    let writeback = user_transmute_w::<SysInfo>(buf)?.ok_or(Errno::EINVAL)?;
    let mut sys_info = SysInfo::default();
    sys_info.uptime = cpu_time().as_secs() as isize;
    sys_info.totalram = total_memory();
    sys_info.freeram = free_user_memory();
    sys_info.procs = MONITORS.lock().process.count() as u16;
    *writeback = sys_info;
    Ok(0)
}
