mod fs;
mod process;
mod system;
mod time;

use fs::*;
use process::*;
use system::*;
use time::*;

use log::warn;
use num_enum::FromPrimitive;
use crate::result::{Errno, SyscallResult};
use crate::strace;

macro_rules! syscall {
    ($handler: ident $(, $args:expr)*) => {
        {
            use crate::processor::current_trap_ctx;
            strace!(
                "{}, args: {:?}, sepc: {:#x}",
                stringify!($handler),
                ($($args,)*),
                current_trap_ctx().sepc
            );
            $handler($($args,)*)
        }
    };
}

macro_rules! async_syscall {
    ($handler: ident $(, $args:expr)*) => {
        {
            use crate::processor::current_trap_ctx;
            strace!(
                "{}, args: {:?}, sepc: {:#x}",
                stringify!($handler),
                ($($args,)*),
                current_trap_ctx().sepc
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
    let code = SyscallCode::from(code);
    match code {
        SyscallCode::Shutdown => syscall!(sys_shutdown),
        SyscallCode::Getcwd => syscall!(sys_getcwd, args[0], args[1]),
        SyscallCode::Dup => syscall!(sys_dup, args[0]),
        SyscallCode::Dup3 => syscall!(sys_dup3, args[0], args[1], args[2] as u32),
        // SyscallCode::Fcntl
        // SyscallCode::Ioctl
        // SyscallCode::Mkdirat
        // SyscallCode::Unlinkat
        // SyscallCode::Umount2
        // SyscallCode::Mount
        // SyscallCode::Statfs
        // SyscallCode::Ftruncate
        // SyscallCode::Faccessat
        // SyscallCode::Chdir
        // SyscallCode::Openat
        // SyscallCode::Close
        // SyscallCode::Pipe2
        // SyscallCode::Getdents64
        // SyscallCode::Lseek
        SyscallCode::Read => async_syscall!(read, args[0], args[1], args[2]),
        SyscallCode::Write => async_syscall!(write, args[0], args[1], args[2]),
        // SyscallCode::Readv
        // SyscallCode::Writev
        // SyscallCode::Pread64
        // SyscallCode::Pwrite64
        // SyscallCode::Sendfile
        // SyscallCode::Pselect6
        // SyscallCode::Ppoll
        // SyscallCode::Readlinkat
        // SyscallCode::Newfstatat
        // SyscallCode::Fstat
        // SyscallCode::Sync
        // SyscallCode::Fsync
        // SyscallCode::Utimensat
        SyscallCode::Exit => syscall!(sys_exit, args[0] as i8),
        // SyscallCode::ExitGroup
        // SyscallCode::SetTidAddress
        // SyscallCode::Futex
        // SyscallCode::Nanosleep
        // SyscallCode::Setitimer
        // SyscallCode::ClockGettime
        // SyscallCode::Syslog
        SyscallCode::SchedYield => async_syscall!(sys_yield),
        // SyscallCode::Kill
        // SyscallCode::Tkill
        // SyscallCode::RtSigsupend
        // SyscallCode::RtSigaction
        // SyscallCode::RtSigprocmask
        // SyscallCode::RtSigtimedwait
        // SyscallCode::RtSigreturn
        // SyscallCode::Times
        SyscallCode::Uname => syscall!(sys_uname, args[0]),
        // SyscallCode::Getrusage
        // SyscallCode::Umask
        SyscallCode::GetTimeOfDay => syscall!(sys_gettimeofday, args[0], args[1]),
        SyscallCode::Getpid => syscall!(sys_getpid),
        SyscallCode::Getppid => syscall!(sys_getppid),
        SyscallCode::Getuid => syscall!(sys_getuid),
        SyscallCode::Geteuid => syscall!(sys_geteuid),
        SyscallCode::Getegid => syscall!(sys_getegid),
        SyscallCode::Gettid => syscall!(sys_gettid),
        // SyscallCode::Sysinfo
        // SyscallCode::Shmget
        // SyscallCode::Shmctl
        // SyscallCode::Shmat
        // SyscallCode::Brk
        // SyscallCode::Munmap
        // SyscallCode::Clone
        // SyscallCode::Execve
        // SyscallCode::Mmap
        // SyscallCode::Mprotect
        // SyscallCode::Madvise
        // SyscallCode::Wait4
        // SyscallCode::Prlimit
        // SyscallCode::Renameat2
        // SyscallCode::Seccomp
        // SyscallCode::Getrandom
        // SyscallCode::MemfdCreate
        // SyscallCode::Membarrier
        // SyscallCode::CopyFileRange
        _ => {
            warn!("Unsupported syscall: {:?}", code);
            Err(Errno::ENOSYS)
        }
    }
}
