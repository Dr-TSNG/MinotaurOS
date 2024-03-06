mod fs;
mod process;

use log::warn;
use num_enum::FromPrimitive;
use crate::result::{Errno, SyscallResult};
use crate::strace;
use crate::syscall::process::{sys_exit, sys_yield};

macro_rules! sys_handler {
    ($handler: ident, $args: tt) => {
        {
            use crate::processor::current_trap_ctx;
            strace!(
                "{}, args: {:?}, sepc: {:#x}",
                stringify!($handler),
                $args,
                current_trap_ctx().sepc
            );
            $handler$args
        }
    };
    ($handler: ident, $args: tt, $await: tt) => {
        {
            use crate::processor::current_trap_ctx;
            strace!(
                "{}, args: {:?}, sepc: {:#x}",
                stringify!($handler),
                $args,
                current_trap_ctx().sepc
            );
            $handler$args.$await
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

pub async fn syscall(code: usize, args: [usize; 6]) -> SyscallResult<isize> {
    let code = SyscallCode::from(code);
    match code {
        SyscallCode::Exit => sys_handler!(sys_exit, (args[0] as i8)),
        SyscallCode::SchedYield => sys_handler!(sys_yield, (), await),
        _ => {
            warn!("Unsupported syscall: {:?}", code);
            Err(Errno::ENOSYS)
        }
    }
}
