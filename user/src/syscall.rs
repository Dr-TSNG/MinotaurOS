use alloc::ffi::CString;
use alloc::vec::Vec;
use core::arch::asm;
use bitflags::bitflags;
use crate::println;
use crate::syscall::SyscallCode::*;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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
}

bitflags! {
    pub struct OpenFlags: u32 {
        const O_RDONLY    =        00;
        const O_WRONLY    =        01;
        const O_RDWR      =        02;
        const O_CREAT     =      0100;
        const O_EXCL      =      0200;
        const O_NOCTTY    =      0400;
        const O_TRUNC     =     01000;
        const O_APPEND    =     02000;
        const O_NONBLOCK  =     04000;
        const O_DSYNC     =    010000;
        const O_ASYNC     =    020000;
        const O_DIRECT    =    040000;
        const O_LARGEFILE =   0100000;
        const O_DIRECTORY =   0200000;
        const O_NOFOLLOW  =   0400000;
        const O_NOATIME   =  01000000;
        const O_CLOEXEC   =  02000000;
        const O_SYNC      =  04010000;
        const O_PATH      = 010000000;
    }
}

pub static AT_FDCWD: i32 = -100;

macro_rules! syscall {
    ($code:expr $(, $args:expr)*) => {
        unsafe {
            syscall_asm!($code as usize $(, $args)*)
        }
    };
}

macro_rules! syscall_asm {
    ($code:expr) => {{
        let result: isize;
        asm!("ecall", in("a7") $code, lateout("a0") result);
        result
    }};
    ($code:expr, $arg0: expr) => {{
        let result: isize;
        asm!("ecall", in("a7") $code, inlateout("a0") $arg0 => result);
        result
    }};
    ($code: expr, $arg0: expr, $arg1: expr) => {{
        let result: isize;
        asm!("ecall", in("a7") $code, inlateout("a0") $arg0 => result, in("a1") $arg1);
        result
    }};
    ($code: expr, $arg0: expr, $arg1: expr, $arg2: expr) => {{
        let result: isize;
        asm!("ecall", in("a7") $code, inlateout("a0") $arg0 => result, in("a1") $arg1, in("a2") $arg2);
        result
    }};
    ($code: expr, $arg0: expr, $arg1: expr, $arg2: expr, $arg3: expr) => {{
        let result: isize;
        asm!("ecall", in("a7") $code, inlateout("a0") $arg0 => result, in("a1") $arg1, in("a2") $arg2, in("a3") $arg3);
        result
    }};
    ($code: expr, $arg0: expr, $arg1: expr, $arg2: expr, $arg3: expr, $arg4: expr) => {{
        let result: isize;
        asm!("ecall", in("a7") $code, inlateout("a0") $arg0 => result, in("a1") $arg1, in("a2") $arg2, in("a3") $arg3, in("a4") $arg4);
        result
    }};
    ($code: expr, $arg0: expr, $arg1: expr, $arg2: expr, $arg3: expr, $arg4: expr, $arg5: expr) => {{
        let result: isize;
        asm!("ecall", in("a7") $code, inlateout("a0") $arg0 => result, in("a1") $arg1, in("a2") $arg2, in("a3") $arg3, in("a4") $arg4, in("a5") $arg5);
        result
    }};
}

pub fn sys_getcwd(buf: usize, len: usize) -> isize {
    syscall!(Getcwd, buf, len)
}

pub fn sys_exit(exit_code: i32) -> isize {
    let exit_code = exit_code as usize;
    syscall!(Exit, exit_code)
}

pub fn sys_open(path: &str, flags: OpenFlags) -> i32 {
    let path = CString::new(path).unwrap();
    syscall!(Openat, AT_FDCWD as usize, path.as_ptr() as usize, flags.bits, 0) as i32
}

pub fn sys_read(fd: i32, buf: &mut [u8]) -> isize {
    syscall!(Read, fd as usize, buf.as_ptr() as usize, buf.len())
}

pub fn sys_write(fd: i32, buf: &[u8]) -> isize {
    syscall!(Write, fd as usize, buf.as_ptr() as usize, buf.len())
}

pub fn sys_yield() -> isize {
    syscall!(SchedYield)
}

pub fn sys_execve(path: &str, argv: &[&str], envp: &[&str]) -> isize {
    let path = CString::new(path).unwrap();
    let argv: Vec<_> = argv.iter().map(|s| CString::new(*s).unwrap()).collect();
    let envp: Vec<_> = envp.iter().map(|s| CString::new(*s).unwrap()).collect();
    let mut argv = argv.iter().map(|s| s.as_ptr() as usize).collect::<Vec<_>>();
    let mut envp = envp.iter().map(|s| s.as_ptr() as usize).collect::<Vec<_>>();
    argv.push(0);
    envp.push(0);
    println!("argv: {:?}, envp: {:?}", argv, envp);
    println!("argv_ptr: {:#x}, envp_ptr: {:#x}", argv.as_ptr() as usize, envp.as_ptr() as usize);
    syscall!(Execve, path.as_ptr() as usize, argv.as_ptr() as usize, envp.as_ptr() as usize)
}
