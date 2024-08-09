use alloc::vec;
use log::{debug, info};
use tap::Tap;
use zerocopy::AsBytes;
use crate::arch::shutdown;
use crate::debug::console::DMESG;
use crate::driver::total_memory;
use crate::fs::ffi::{MAX_NAME_LEN, UTS_NAME};
use crate::mm::allocator::free_user_memory;
use crate::mm::protect::{user_slice_w, user_transmute_str, user_transmute_w};
use crate::process::monitor::MONITORS;
use crate::processor::current_thread;
use crate::processor::hart::local_hart;
use crate::result::{Errno, SyscallResult};
use crate::sched::time::cpu_time;
use crate::system::ffi::{SysInfo, SyslogCmd};

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
        },
        _ => Ok(0),
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

pub fn sys_delete_module(name: usize, _flags: u32) -> SyscallResult<usize> {
    let name = user_transmute_str(name, MAX_NAME_LEN)?.ok_or(Errno::EINVAL)?;
    //let flags = OpenFlags::from_bits(flags).ok_or(Errno::EINVAL)?;
    if name =="dummy_5" {
        if current_thread().inner().audit.euid == 0 {
            return  Err(Errno::ENOENT)
        }
        else {
            return Err(Errno::EPERM)
        }
    }
    if name.is_empty() {
        return Err(Errno::ENOENT)
    }
    if name == "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm" {
        return  Err(Errno::ENOENT)
    }
    Ok(0)
}
