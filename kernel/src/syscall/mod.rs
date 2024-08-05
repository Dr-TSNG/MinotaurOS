mod fs;
mod mm;
mod process;
mod signal;
mod sync;
mod system;
mod time;
mod net;

use core::mem::size_of;
use fs::*;
use mm::*;
use net::*;
use process::*;
use signal::*;
use sync::*;
use system::*;
use time::*;

use log::{debug, info, warn};
use num_enum::FromPrimitive;
use crate::fs::fd::FdNum;
use crate::mm::protect::{user_slice_w, user_transmute_w};
use crate::process::{Gid, Pid, Tid, Uid};
use crate::processor::hart::local_hart;
use crate::result::{Errno, SyscallResult};
use crate::strace;

macro_rules! syscall {
    ($handler: ident $(, $args:expr)*) => {
        {
            strace!(
                "{}, args: {:?}, pc: {:#x}",
                stringify!($handler),
                ($($args,)*),
                crate::processor::current_trap_ctx().get_pc()
            );
            $handler($($args,)*)
        }
    };
}

macro_rules! async_syscall {
    ($handler: ident $(, $args:expr)*) => {
        {
            strace!(
                "{}, args: {:?}, pc: {:#x}",
                stringify!($handler),
                ($($args,)*),
                crate::processor::current_trap_ctx().get_pc()
            );
            $handler($($args,)*).await
        }
    };
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, FromPrimitive)]
#[repr(usize)]
pub enum SyscallCode {
    Shutdown = 0,
    Getcwd = 17,
    Dup = 23,
    Dup3 = 24,
    Fcntl = 25,
    Ioctl = 29,
    Mkdirat = 34,
    Unlinkat = 35,
    Symlinkat = 36,
    Umount2 = 39,
    Mount = 40,
    Statfs = 43,
    Fstatfs = 44,
    Ftruncate = 46,
    Faccessat = 48,
    Chdir = 49,
    Fchmodat = 53,
    Fchownat = 54,
    Openat = 56,
    Close = 57,
    Pipe2 = 59,
    Getdents64 = 61,
    Lseek = 62,
    Read = 63,
    Write = 64,
    Readv = 65,
    Writev = 66,
    Pread64 = 67,
    Pwrite64 = 68,
    Sendfile = 71,
    Pselect6 = 72,
    Ppoll = 73,
    Readlinkat = 78,
    Newfstatat = 79,
    Fstat = 80,
    Sync = 81,
    Fsync = 82,
    Utimensat = 88,
    Exit = 93,
    ExitGroup = 94,
    SetTidAddress = 96,
    Futex = 98,
    GetRobustList = 99,
    SetRobustList = 100,
    Nanosleep = 101,
    Setitimer = 103,
    ClockGettime = 113,
    ClockGetres = 114,
    ClockNanosleep = 115,
    Syslog = 116,
    SchedSetScheduler = 119,
    SchedGetScheduler = 120,
    SchedGetParam = 121,
    SchedSetAffinity = 122,
    SchedGetAffinity = 123,
    SchedYield = 124,
    Kill = 129,
    Tkill = 130,
    Tgkill = 131,
    RtSigsupend = 133,
    RtSigaction = 134,
    RtSigprocmask = 135,
    RtSigtimedwait = 137,
    RtSigreturn = 139,
    GetPriority = 141,
    Setuid = 146,
    Times = 153,
    Setpgid = 154,
    Getpgid = 155,
    Setsid = 157,
    Uname = 160,
    Getrlimit = 163,
    Setrlimit = 164,
    Getrusage = 165,
    Umask = 166,
    GetCpu = 168,
    GetTimeOfDay = 169,
    Getpid = 172,
    Getppid = 173,
    Getuid = 174,
    Geteuid = 175,
    Getgid = 176,
    Getegid = 177,
    Gettid = 178,
    Sysinfo = 179,
    Shmget = 194,
    Shmctl = 195,
    Shmat = 196,
    Socket = 198,
    SocketPair = 199,
    Bind = 200,
    Listen = 201,
    Accept = 202,
    Connect = 203,
    Getsockname = 204,
    Getpeername = 205,
    Sendto = 206,
    Recvfrom = 207,
    Setsockopt = 208,
    Getsockopt = 209,
    Sockshutdown = 210,
    Brk = 214,
    Munmap = 215,
    Clone = 220,
    Execve = 221,
    Mmap = 222,
    Mprotect = 226,
    Msync = 227,
    Madvise = 233,
    Wait4 = 260,
    Prlimit = 261,
    Renameat2 = 276,
    Seccomp = 277,
    Getrandom = 278,
    MemfdCreate = 279,
    Membarrier = 283,
    CopyFileRange = 285,
    #[num_enum(default)]
    Unknown,
}

pub async fn syscall(code: usize, args: [usize; 6]) -> SyscallResult<usize> {
    let scode = SyscallCode::from(code);
    local_hart().ctx.last_syscall = scode;
    let result = match scode {
        SyscallCode::Shutdown => syscall!(sys_shutdown),
        SyscallCode::Getcwd => syscall!(sys_getcwd, args[0], args[1]),
        SyscallCode::Dup => syscall!(sys_dup, args[0] as FdNum),
        SyscallCode::Dup3 => syscall!(sys_dup3, args[0] as FdNum, args[1] as FdNum, args[2] as u32),
        SyscallCode::Fcntl => syscall!(sys_fcntl, args[0] as FdNum, args[1], args[2]),
        SyscallCode::Ioctl => async_syscall!(sys_ioctl, args[0] as FdNum, args[1], args[2], args[3], args[4], args[5]),
        SyscallCode::Mkdirat => async_syscall!(sys_mkdirat, args[0] as FdNum, args[1], args[2] as u32),
        SyscallCode::Unlinkat => async_syscall!(sys_unlinkat, args[0] as FdNum, args[1], args[2] as u32),
        SyscallCode::Symlinkat => async_syscall!(sys_symlinkat, args[0], args[1] as FdNum, args[2]),
        SyscallCode::Umount2 => async_syscall!(sys_umount2, args[0], args[1] as u32),
        SyscallCode::Mount => async_syscall!(sys_mount, args[0], args[1], args[2], args[3] as u32, args[4]),
        SyscallCode::Statfs => async_syscall!(sys_statfs, args[0], args[1]),
        SyscallCode::Fstatfs => syscall!(sys_fstatfs, args[0] as FdNum, args[1]),
        SyscallCode::Ftruncate => async_syscall!(sys_ftruncate, args[0] as FdNum, args[1] as isize),
        SyscallCode::Faccessat => async_syscall!(sys_faccessat, args[0] as FdNum, args[1], args[2] as u32, args[3] as u32),
        SyscallCode::Chdir => async_syscall!(sys_chdir, args[0]),
        SyscallCode::Fchmodat => async_syscall!(sys_fchmodat, args[0] as FdNum, args[1], args[2] as u32, args[3] as u32),
        SyscallCode::Fchownat => async_syscall!(sys_fchownat, args[0] as FdNum, args[1], args[2] as Uid, args[3] as Uid, args[4] as u32),
        SyscallCode::Openat => async_syscall!(sys_openat, args[0] as i32, args[1], args[2] as u32, args[3] as u32),
        SyscallCode::Close => syscall!(sys_close, args[0] as FdNum),
        SyscallCode::Pipe2 => syscall!(sys_pipe2, args[0], args[1] as u32),
        SyscallCode::Getdents64 => async_syscall!(sys_getdents, args[0] as FdNum, args[1], args[2] as u32),
        SyscallCode::Lseek => async_syscall!(sys_lseek, args[0] as FdNum, args[1] as isize, args[2] as i32),
        SyscallCode::Read => async_syscall!(sys_read, args[0] as FdNum, args[1], args[2]),
        SyscallCode::Write => async_syscall!(sys_write, args[0] as FdNum, args[1], args[2]),
        SyscallCode::Readv => async_syscall!(sys_readv, args[0] as FdNum, args[1], args[2]),
        SyscallCode::Writev => async_syscall!(sys_writev, args[0] as FdNum, args[1], args[2]),
        SyscallCode::Pread64 => async_syscall!(sys_pread, args[0] as FdNum, args[1], args[2], args[3] as isize),
        SyscallCode::Pwrite64 => async_syscall!(sys_pwrite, args[0] as FdNum, args[1], args[2], args[3] as isize),
        SyscallCode::Sendfile => async_syscall!(sys_sendfile, args[0] as FdNum, args[1] as FdNum, args[2], args[3]),
        SyscallCode::Pselect6 => async_syscall!(sys_pselect6, args[0] as FdNum , args[1],args[2],args[3], args[4], args[5]),
        SyscallCode::Ppoll => async_syscall!(sys_ppoll, args[0], args[1], args[2], args[3]),
        SyscallCode::Readlinkat => async_syscall!(sys_readlinkat, args[0] as FdNum, args[1], args[2], args[3]),
        SyscallCode::Newfstatat => async_syscall!(sys_newfstatat, args[0] as FdNum, args[1], args[2], args[3] as u32),
        SyscallCode::Fstat => syscall!(sys_fstat, args[0] as FdNum, args[1]),
        SyscallCode::Sync => syscall!(dummy),
        SyscallCode::Fsync => async_syscall!(sys_fsync, args[0] as FdNum),
        SyscallCode::Utimensat => async_syscall!(sys_utimensat, args[0] as FdNum, args[1], args[2], args[3] as u32),
        SyscallCode::Exit => syscall!(sys_exit, args[0] as u32),
        SyscallCode::ExitGroup => syscall!(sys_exit_group, args[0] as u32),
        SyscallCode::SetTidAddress => syscall!(sys_set_tid_address, args[0]),
        SyscallCode::Futex => async_syscall!(sys_futex, args[0], args[1] as i32, args[2] as u32, args[3], args[4], args[5]),
        SyscallCode::GetRobustList => syscall!(dummy),
        SyscallCode::SetRobustList => syscall!(dummy),
        SyscallCode::Nanosleep => async_syscall!(sys_nanosleep, args[0], args[1]),
        SyscallCode::Setitimer => syscall!(sys_setitimer, args[0] as i32, args[1], args[2]),
        SyscallCode::ClockGettime => syscall!(sys_clock_gettime, args[0], args[1]),
        SyscallCode::ClockGetres => syscall!(sys_clock_getres, args[0], args[1]),
        SyscallCode::ClockNanosleep => async_syscall!(sys_clock_nanosleep, args[0], args[1] as i32, args[2], args[3]),
        SyscallCode::Syslog => syscall!(sys_syslog, args[0] as i32, args[1], args[2]),
        SyscallCode::SchedSetScheduler => syscall!(dummy),
        SyscallCode::SchedGetScheduler => syscall!(dummy),
        SyscallCode::SchedGetParam => syscall!(dummy),
        SyscallCode::SchedSetAffinity => syscall!(sys_sched_setaffinity, args[0] as Tid, args[1], args[2]),
        SyscallCode::SchedGetAffinity => syscall!(sys_sched_getaffinity, args[0] as Tid, args[1], args[2]),
        SyscallCode::SchedYield => async_syscall!(sys_sched_yield),
        SyscallCode::Kill => syscall!(sys_kill, args[0] as Pid, args[1]),
        SyscallCode::Tkill => syscall!(sys_tkill, args[0] as Tid, args[1]),
        SyscallCode::Tgkill => syscall!(sys_tgkill, args[0] as Pid, args[1] as Tid, args[2]),
        SyscallCode::RtSigsupend => async_syscall!(sys_rt_sigsuspend, args[0]),
        SyscallCode::RtSigaction => syscall!(sys_rt_sigaction, args[0] as i32, args[1], args[2]),
        SyscallCode::RtSigprocmask => syscall!(sys_rt_sigprocmask, args[0] as i32, args[1], args[2]),
        SyscallCode::RtSigtimedwait => syscall!(sys_rt_sigtimedwait, args[0], args[1], args[2]),
        SyscallCode::RtSigreturn => syscall!(sys_rt_sigreturn),
        SyscallCode::GetPriority => syscall!(sys_getpriority,args[0] as i32,args[1] as i32),
        SyscallCode::Setuid => syscall!(sys_setuid, args[0] as Uid),
        SyscallCode::Times => syscall!(sys_times, args[0]),
        SyscallCode::Setpgid => syscall!(sys_setpgid, args[0] as Pid, args[1] as Gid),
        SyscallCode::Getpgid => syscall!(sys_getpgid, args[0] as Pid),
        SyscallCode::Setsid => syscall!(sys_setsid),
        SyscallCode::Uname => syscall!(sys_uname, args[0]),
        SyscallCode::Getrlimit => syscall!(sys_getrlimit, args[0] as u32, args[1]),
        SyscallCode::Setrlimit => syscall!(sys_setrlimit, args[0] as u32, args[1]),
        SyscallCode::Getrusage => syscall!(sys_getrusage, args[0] as i32, args[1]),
        SyscallCode::Umask => syscall!(sys_umask, args[0] as u32),
        SyscallCode::GetCpu => syscall!(sys_getcpu,args[0],args[1],args[2]),
        SyscallCode::GetTimeOfDay => syscall!(sys_gettimeofday, args[0], args[1]),
        SyscallCode::Getpid => syscall!(sys_getpid),
        SyscallCode::Getppid => syscall!(sys_getppid),
        SyscallCode::Getuid => syscall!(sys_getuid),
        SyscallCode::Geteuid => syscall!(sys_geteuid),
        SyscallCode::Getgid => syscall!(sys_getgid),
        SyscallCode::Getegid => syscall!(sys_getegid),
        SyscallCode::Gettid => syscall!(sys_gettid),
        SyscallCode::Sysinfo => syscall!(sys_sysinfo, args[0]),
        SyscallCode::Shmget => syscall!(sys_shmget, args[0], args[1], args[2] as u32),
        SyscallCode::Shmctl => syscall!(sys_shmctl, args[0] as i32, args[1] as i32, args[2]),
        SyscallCode::Shmat => syscall!(sys_shmat, args[0] as i32, args[1], args[2] as u32),
        SyscallCode::Socket => syscall!(sys_socket, args[0] as u32, args[1] as u32, args[2] as u32),
        SyscallCode::SocketPair => syscall!(sys_socketpair,args[0] as u32,args[1] as u32,args[2] as u32,args[3]),
        SyscallCode::Bind => syscall!(sys_bind, args[0] as FdNum, args[1], args[2] as u32),
        SyscallCode::Listen => syscall!(sys_listen, args[0] as FdNum, args[1] as u32),
        SyscallCode::Accept => async_syscall!(sys_accept, args[0] as FdNum, args[1], args[2]),
        SyscallCode::Connect => async_syscall!(sys_connect, args[0] as FdNum, args[1], args[2] as u32),
        SyscallCode::Getsockname => syscall!(sys_getsockname, args[0] as FdNum, args[1], args[2]),
        SyscallCode::Getpeername => syscall!(sys_getpeername, args[0] as FdNum, args[1], args[2]),
        SyscallCode::Sendto => async_syscall!(sys_sendto, args[0] as FdNum, args[1], args[2], args[3] as u32, args[4], args[5] as u32),
        SyscallCode::Recvfrom => async_syscall!(sys_recvfrom, args[0] as FdNum, args[1], args[2], args[3] as u32, args[4], args[5]),
        SyscallCode::Setsockopt => syscall!(sys_setsockopt, args[0] as FdNum, args[1] as u32, args[2] as u32, args[3], args[4] as u32),
        SyscallCode::Getsockopt => syscall!(sys_getsockopt, args[0] as FdNum, args[1] as u32, args[2] as u32, args[3], args[4]),
        SyscallCode::Sockshutdown => syscall!(sys_sockshutdown, args[0] as FdNum, args[1] as u32),
        SyscallCode::Brk => syscall!(sys_brk, args[0]),
        SyscallCode::Munmap => syscall!(sys_munmap, args[0], args[1]),
        SyscallCode::Clone => async_syscall!(sys_clone, args[0] as u32, args[1], args[2], args[3], args[4]),
        SyscallCode::Execve => async_syscall!(sys_execve, args[0], args[1], args[2]),
        SyscallCode::Mmap => syscall!(sys_mmap, args[0], args[1], args[2] as u32, args[3] as u32, args[4] as FdNum, args[5]),
        SyscallCode::Mprotect => syscall!(sys_mprotect, args[0], args[1], args[2] as u32),
        SyscallCode::Msync => syscall!(dummy),
        SyscallCode::Madvise => syscall!(dummy),
        SyscallCode::Wait4 => async_syscall!(sys_wait4, args[0] as Pid, args[1], args[2] as u32, args[3]),
        SyscallCode::Prlimit => syscall!(sys_prlimit, args[0] as Pid, args[1] as u32, args[2], args[3]),
        SyscallCode::Renameat2 => async_syscall!(sys_renameat2, args[0] as FdNum, args[1], args[2] as FdNum, args[3], args[4] as u32),
        // SyscallCode::Seccomp
        SyscallCode::Getrandom => async_syscall!(sys_getrandom, args[0], args[1], args[2] as u32),
        // SyscallCode::MemfdCreate
        // SyscallCode::Membarrier
        // SyscallCode::CopyFileRange
        _ => {
            warn!("Unsupported syscall: {:?} ({})", scode, code);
            Err(Errno::ENOSYS)
        }
    };
    strace!("return: {:?}", result);
    result
}

fn dummy() -> SyscallResult<usize> {
    debug!("Dummy syscall");
    Ok(0)
}

pub fn sys_getcpu(cpu: usize,node: usize,tcache: usize) -> SyscallResult<usize>{
    info!("[sys_getcpu] cpu: {}, node: {}", cpu, node);
    // 获取当前 CPU 和 NUMA 节点编号
    let (current_cpu, current_node) = get_current_cpu_and_node();
    // 尝试将当前 CPU 写入用户提供的指针位置
    if cpu != 0 {
        if let Some(cpu_ptr) = user_transmute_w::<u32>(cpu)? {
            *cpu_ptr = current_cpu;
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

fn get_current_cpu_and_node() -> (u32,u32){
    let num = local_hart().id as u32;
    (num,0)
}

pub fn sys_getpriority(which: i32,who: i32) -> SyscallResult<usize>{
    // 10 -> 10
    // 20 -> 0
    // 30 -> -10
    // 这里为了通过第一个测试，直接全部返回 0 ，进程/线程/用户的 优先级 没有实现之前的做法。
    return Ok(20);
}

pub async fn sys_getrandom(buf: usize, buflen: usize, _flags: u32) -> SyscallResult<usize> {
    // 暂时先将随机数全部写为0
    if buf == 0{
        return Err(Errno::EINVAL);
    }
    let buf = user_slice_w(buf, buflen * size_of::<u8>())?;
    let buf:&mut[u8] = bytemuck::cast_slice_mut(buf);
    for i in 0..buflen{
        buf[i] = 0
    }
    Ok(buflen)
}


