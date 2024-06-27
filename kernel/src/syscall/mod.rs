mod fs;
mod mm;
mod process;
mod signal;
mod sync;
mod system;
mod time;

use fs::*;
use mm::*;
use process::*;
use signal::*;
use sync::*;
use system::*;
use time::*;

use log::warn;
use num_enum::FromPrimitive;
use crate::fs::fd::FdNum;
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
    Umount2 = 39,
    Mount = 40,
    Statfs = 43,
    Fstatfs = 44,
    Ftruncate = 46,
    Faccessat = 48,
    Chdir = 49,
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
    Syslog = 116,
    SchedYield = 124,
    Kill = 129,
    Tkill = 130,
    RtSigsupend = 133,
    RtSigaction = 134,
    RtSigprocmask = 135,
    RtSigtimedwait = 137,
    RtSigreturn = 139,
    Times = 153,
    Uname = 160,
    Getrlimit = 163,
    Setrlimit = 164,
    Getrusage = 165,
    Umask = 166,
    GetTimeOfDay = 169,
    Getpid = 172,
    Getppid = 173,
    Getuid = 174,
    Geteuid = 175,
    Getegid = 177,
    Gettid = 178,
    Sysinfo = 179,
    Shmget = 194,
    Shmctl = 195,
    Shmat = 196,
    Brk = 214,
    Munmap = 215,
    Clone = 220,
    Execve = 221,
    Mmap = 222,
    Mprotect = 226,
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
    let result = match scode {
        SyscallCode::Shutdown => syscall!(sys_shutdown),
        SyscallCode::Getcwd => syscall!(sys_getcwd, args[0], args[1]),
        SyscallCode::Dup => syscall!(sys_dup, args[0] as FdNum),
        SyscallCode::Dup3 => syscall!(sys_dup3, args[0] as FdNum, args[1] as FdNum, args[2] as u32),
        SyscallCode::Fcntl => syscall!(sys_fcntl, args[0] as FdNum, args[1], args[2]),
        SyscallCode::Ioctl => async_syscall!(sys_ioctl, args[0] as FdNum, args[1], args[2], args[3], args[4], args[5]),
        SyscallCode::Mkdirat => async_syscall!(sys_mkdirat, args[0] as FdNum, args[1], args[2] as u32),
        SyscallCode::Unlinkat => async_syscall!(sys_unlinkat, args[0] as FdNum, args[1], args[2] as u32),
        SyscallCode::Umount2 => async_syscall!(sys_umount2, args[0], args[1] as u32),
        SyscallCode::Mount => async_syscall!(sys_mount, args[0], args[1], args[2], args[3] as u32, args[4]),
        SyscallCode::Statfs => async_syscall!(sys_statfs, args[0], args[1]),
        SyscallCode::Fstatfs => syscall!(sys_fstatfs, args[0] as FdNum, args[1]),
        SyscallCode::Ftruncate => async_syscall!(sys_ftruncate, args[0] as FdNum, args[1] as isize),
        SyscallCode::Faccessat => async_syscall!(sys_faccessat, args[0] as FdNum, args[1], args[2] as u32, args[3] as u32),
        SyscallCode::Chdir => async_syscall!(sys_chdir, args[0]),
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
        // SyscallCode::Readlinkat
        SyscallCode::Newfstatat => async_syscall!(sys_newfstatat, args[0] as FdNum, args[1], args[2], args[3] as u32),
        SyscallCode::Fstat => syscall!(sys_fstat, args[0] as FdNum, args[1]),
        // SyscallCode::Sync
        SyscallCode::Fsync => async_syscall!(sys_fsync, args[0] as FdNum),
        SyscallCode::Utimensat => async_syscall!(sys_utimensat, args[0] as FdNum, args[1], args[2], args[3] as u32),
        SyscallCode::Exit => syscall!(sys_exit, args[0] as i8),
        SyscallCode::ExitGroup => syscall!(sys_exit_group, args[0] as i8),
        SyscallCode::SetTidAddress => syscall!(sys_set_tid_address, args[0]),
        SyscallCode::Futex => async_syscall!(sys_futex, args[0], args[1] as i32, args[2] as u32, args[3], args[4], args[5]),
        SyscallCode::GetRobustList => syscall!(sys_get_robust_list, args[0], args[1], args[2]),
        SyscallCode::SetRobustList => syscall!(sys_set_robust_list, args[0], args[1]),
        SyscallCode::Nanosleep => async_syscall!(sys_nanosleep, args[0], args[1]),
        // SyscallCode::Setitimer
        SyscallCode::ClockGettime => syscall!(sys_clock_gettime, args[0], args[1]),
        SyscallCode::Syslog => syscall!(sys_syslog, args[0] as i32, args[1], args[2]),
        SyscallCode::SchedYield => async_syscall!(sys_yield),
        SyscallCode::Kill => syscall!(sys_kill, args[0], args[1]),
        SyscallCode::Tkill => syscall!(sys_tkill, args[0], args[1]),
        SyscallCode::RtSigsupend => async_syscall!(sys_rt_sigsuspend, args[0]),
        SyscallCode::RtSigaction => syscall!(sys_rt_sigaction, args[0] as i32, args[1], args[2]),
        SyscallCode::RtSigprocmask => syscall!(sys_rt_sigprocmask, args[0] as i32, args[1], args[2]),
        SyscallCode::RtSigtimedwait => syscall!(sys_rt_sigtimedwait, args[0], args[1], args[2]),
        SyscallCode::RtSigreturn => syscall!(sys_rt_sigreturn),
        SyscallCode::Times => syscall!(sys_times, args[0]),
        SyscallCode::Uname => syscall!(sys_uname, args[0]),
        SyscallCode::Getrlimit => syscall!(sys_getrlimit, args[0] as u32, args[1]),
        SyscallCode::Setrlimit => syscall!(sys_setrlimit, args[0] as u32, args[1]),
        // SyscallCode::Getrusage
        // SyscallCode::Umask
        SyscallCode::GetTimeOfDay => syscall!(sys_gettimeofday, args[0], args[1]),
        SyscallCode::Getpid => syscall!(sys_getpid),
        SyscallCode::Getppid => syscall!(sys_getppid),
        SyscallCode::Getuid => syscall!(sys_getuid),
        SyscallCode::Geteuid => syscall!(sys_geteuid),
        SyscallCode::Getegid => syscall!(sys_getegid),
        SyscallCode::Gettid => syscall!(sys_gettid),
        SyscallCode::Sysinfo => syscall!(sys_sysinfo, args[0]),
        // SyscallCode::Shmget
        // SyscallCode::Shmctl
        // SyscallCode::Shmat
        SyscallCode::Brk => syscall!(sys_brk, args[0]),
        SyscallCode::Munmap => syscall!(sys_munmap, args[0], args[1]),
        SyscallCode::Clone => syscall!(sys_clone, args[0] as u32, args[1], args[2], args[3], args[4]),
        SyscallCode::Execve => async_syscall!(sys_execve, args[0], args[1], args[2]),
        SyscallCode::Mmap => syscall!(sys_mmap, args[0], args[1], args[2] as u32, args[3] as u32, args[4] as FdNum, args[5]),
        SyscallCode::Mprotect => syscall!(sys_mprotect, args[0], args[1], args[2] as u32),
        // SyscallCode::Madvise
        SyscallCode::Wait4 => async_syscall!(sys_wait4, args[0], args[1], args[2] as u32, args[3]),
        SyscallCode::Prlimit => syscall!(sys_prlimit, args[0], args[1] as u32, args[2], args[3]),
        SyscallCode::Renameat2 => async_syscall!(sys_renameat2, args[0] as FdNum, args[1], args[2] as FdNum, args[3], args[4] as u32),
        // SyscallCode::Seccomp
        // SyscallCode::Getrandom
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
