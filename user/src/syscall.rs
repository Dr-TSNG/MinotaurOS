use alloc::ffi::CString;
use alloc::vec::Vec;
use core::arch::asm;
use core::ptr::null;
use bitflags::bitflags;
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
        const O_RDONLY    =        0o0;
        const O_WRONLY    =        0o1;
        const O_RDWR      =        0o2;
        const O_CREAT     =      0o100;
        const O_EXCL      =      0o200;
        const O_NOCTTY    =      0o400;
        const O_TRUNC     =     0o1000;
        const O_APPEND    =     0o2000;
        const O_NONBLOCK  =     0o4000;
        const O_DSYNC     =    0o10000;
        const O_ASYNC     =    0o20000;
        const O_DIRECT    =    0o40000;
        const O_LARGEFILE =   0o100000;
        const O_DIRECTORY =   0o200000;
        const O_NOFOLLOW  =   0o400000;
        const O_NOATIME   =  0o1000000;
        const O_CLOEXEC   =  0o2000000;
        const O_SYNC      =  0o4010000;
        const O_PATH      = 0o10000000;
    }
}

#[repr(C)]
struct TimeSpec {
    tv_sec: usize,
    tv_nsec: usize,
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct SigAction {
    pub sa_handler: usize,
    pub sa_flags: u32,
    pub sa_restorer: usize,
    pub sa_mask: SigSet,
}

pub const SIGHUP: i32 = 1;
pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGILL: i32 = 4;
pub const SIGTRAP: i32 = 5;
pub const SIGABRT: i32 = 6;
pub const SIGBUS: i32 = 7;
pub const SIGFPE: i32 = 8;
pub const SIGKILL: i32 = 9;
pub const SIGUSR1: i32 = 10;
pub const SIGSEGV: i32 = 11;
pub const SIGUSR2: i32 = 12;
pub const SIGPIPE: i32 = 13;
pub const SIGALRM: i32 = 14;
pub const SIGTERM: i32 = 15;
pub const SIGSTKFLT: i32 = 16;
pub const SIGCHLD: i32 = 17;
pub const SIGCONT: i32 = 18;
pub const SIGSTOP: i32 = 19;
pub const SIGTSTP: i32 = 20;
pub const SIGTTIN: i32 = 21;
pub const SIGTTOU: i32 = 22;
pub const SIGURG: i32 = 23;
pub const SIGXCPU: i32 = 24;
pub const SIGXFSZ: i32 = 25;
pub const SIGVTALRM: i32 = 26;
pub const SIGPROF: i32 = 27;
pub const SIGWINCH: i32 = 28;
pub const SIGIO: i32 = 29;
pub const SIGPWR: i32 = 30;
pub const SIGSYS: i32 = 31;

pub const SIG_BLOCK: u32 = 0;
pub const SIG_UNBLOCK: u32 = 1;
pub const SIG_SETMASK: u32 = 2;

bitflags! {
    #[derive(Default)]
    pub struct SigSet: u64 {
        const SIGHUP    = 1 << (1 - 1);
        const SIGINT    = 1 << (2 - 1);
        const SIGQUIT   = 1 << (3 - 1);
        const SIGILL    = 1 << (4 - 1);
        const SIGTRAP   = 1 << (5 - 1);
        const SIGABRT   = 1 << (6 - 1);
        const SIGBUS    = 1 << (7 - 1);
        const SIGFPE    = 1 << (8 - 1);
        const SIGKILL   = 1 << (9 - 1);
        const SIGUSR1   = 1 << (10 - 1);
        const SIGSEGV   = 1 << (11 - 1);
        const SIGUSR2   = 1 << (12 - 1);
        const SIGPIPE   = 1 << (13 - 1);
        const SIGALRM   = 1 << (14 - 1);
        const SIGTERM   = 1 << (15 - 1);
        const SIGSTKFLT = 1 << (16 - 1);
        const SIGCHLD   = 1 << (17 - 1);
        const SIGCONT   = 1 << (18 - 1);
        const SIGSTOP   = 1 << (19 - 1);
        const SIGTSTP   = 1 << (20 - 1);
        const SIGTTIN   = 1 << (21 - 1);
        const SIGTTOU   = 1 << (22 - 1);
        const SIGURG    = 1 << (23 - 1);
        const SIGXCPU   = 1 << (24 - 1);
        const SIGXFSZ   = 1 << (25 - 1);
        const SIGVTALRM = 1 << (26 - 1);
        const SIGPROF   = 1 << (27 - 1);
        const SIGWINCH  = 1 << (28 - 1);
        const SIGIO     = 1 << (29 - 1);
        const SIGPWR    = 1 << (30 - 1);
        const SIGSYS    = 1 << (31 - 1);
    }
}

bitflags! {
    pub struct VfsFlags: u32 {
        /// Mount read-only
        const ST_RDONLY      = 1;
        /// Ignore suid and sgid bits
        const ST_NOSUID      = 1 << 1;
        /// Disallow access to device special files
        const ST_NODEV       = 1 << 2;
        /// Disallow program execution
        const ST_NOEXEC      = 1 << 3;
        /// Writes are synced at once
        const ST_SYNCHRONOUS = 1 << 4;
        /// Allow mandatory locks on an FS
        const ST_MANDLOCK    = 1 << 6;
        /// Write on file/directory/symlink
        const ST_WRITE       = 1 << 7;
        /// Append-only file
        const ST_APPEND      = 1 << 8;
        /// Immutable file
        const ST_IMMUTABLE   = 1 << 9;
        /// Do not update access times
        const ST_NOATIME     = 1 << 10;
        /// Do not update directory access times
        const ST_NODIRATIME  = 1 << 11;
        /// Update atime relative to mtime/ctime
        const ST_RELATIME    = 1 << 12;
        /// Do not follow symlinks
        const ST_NOSYMFOLLOW = 1 << 13;
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

pub fn sys_mkdir(path: &str, mode: u32) -> isize {
    let path = CString::new(path).unwrap();
    syscall!(Mkdirat, AT_FDCWD as usize, path.as_ptr() as usize, mode)
}

pub fn sys_getcwd(buf: usize, len: usize) -> isize {
    syscall!(Getcwd, buf, len)
}

pub fn sys_exit(exit_code: i32) -> ! {
    let exit_code = exit_code as usize;
    syscall!(Exit, exit_code);
    unreachable!()
}

pub fn sys_exit_group(exit_code: i32) -> ! {
    let exit_code = exit_code as usize;
    syscall!(ExitGroup, exit_code);
    unreachable!()
}

pub fn sys_access(path: &str, mode: u32) -> isize {
    let path = CString::new(path).unwrap();
    syscall!(Faccessat, AT_FDCWD as usize, path.as_ptr() as usize, mode, 0)
}

pub fn sys_open(path: &str, flags: OpenFlags) -> i32 {
    let path = CString::new(path).unwrap();
    syscall!(Openat, AT_FDCWD as usize, path.as_ptr() as usize, flags.bits, 0) as i32
}

pub fn sys_close(fd: i32) -> isize {
    syscall!(Close, fd as usize)
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

pub fn sys_fork() -> isize {
    syscall!(Clone, 0usize, 0, 0, 0, 0)
}

pub fn sys_execve(path: &str, argv: &[&str], envp: &[&str]) -> isize {
    let path = CString::new(path).unwrap();
    let argv: Vec<_> = argv.iter().map(|s| CString::new(*s).unwrap()).collect();
    let envp: Vec<_> = envp.iter().map(|s| CString::new(*s).unwrap()).collect();
    let mut argv = argv.iter().map(|s| s.as_ptr() as usize).collect::<Vec<_>>();
    let mut envp = envp.iter().map(|s| s.as_ptr() as usize).collect::<Vec<_>>();
    argv.push(0);
    envp.push(0);
    syscall!(Execve, path.as_ptr() as usize, argv.as_ptr() as usize, envp.as_ptr() as usize)
}

pub fn sys_waitpid(pid: isize, status: &mut i32) -> isize {
    syscall!(Wait4, pid, status as *mut i32, 0, 0)
}

pub fn sys_sleep(sec: usize, nsec: usize) -> isize {
    let ts = TimeSpec {
        tv_sec: sec,
        tv_nsec: nsec,
    };
    syscall!(Nanosleep, &ts as *const TimeSpec, 0)
}

pub fn sys_getpid() -> isize {
    syscall!(Getpid)
}

pub fn sys_kill(pid: usize, signal: i32) -> isize {
    syscall!(Kill, pid, signal)
}

pub fn sys_pipe(pipe: &mut [i32; 2]) -> isize {
    syscall!(Pipe2, pipe.as_mut_ptr() as usize, 0)
}

pub fn sys_dup2(oldfd: i32, newfd: i32) -> isize {
    syscall!(Dup3, oldfd as usize, newfd as usize, 0)
}

pub fn sigaction(sig: i32, new: Option<&SigAction>, old: Option<&mut SigAction>) -> isize {
    let new_ptr = new.map_or(0, |n| n as *const SigAction as usize);
    let old_ptr = old.map_or(0, |o| o as *mut SigAction as usize);
    syscall!(RtSigaction, sig as usize, new_ptr, old_ptr, 8)
}

pub fn sigprocmask(how: u32, set: Option<&SigSet>, oldset: Option<&mut SigSet>) -> isize {
    let set_ptr = set.map_or(0, |s| s as *const SigSet as usize);
    let oldset_ptr = oldset.map_or(0, |s| s as *mut SigSet as usize);
    syscall!(RtSigprocmask, how as usize, set_ptr, oldset_ptr, 8)
}

pub fn mount(source: &str, target: &str, fstype: &str, flags: VfsFlags, data: Option<&str>) -> isize {
    let source = CString::new(source).unwrap();
    let target = CString::new(target).unwrap();
    let fstype = CString::new(fstype).unwrap();
    let data = data.map(|s| CString::new(s).unwrap());
    let data = data.as_ref().map(|s| s.as_ptr()).unwrap_or(null());
    syscall!(Mount, source.as_ptr(), target.as_ptr(), fstype.as_ptr(), flags.bits, data)
}
