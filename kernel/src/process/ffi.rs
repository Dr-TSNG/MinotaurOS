use bitflags::bitflags;
use num_enum::TryFromPrimitive;
use zerocopy::AsBytes;
use crate::sched::ffi::TimeVal;

bitflags! {
    pub struct CloneFlags: u32 {
        const SIGCHLD = 17;
        const CLONE_VM = 1 << 8;
        const CLONE_FS = 1 << 9;
        const CLONE_FILES = 1 << 10;
        const CLONE_SIGHAND = 1 << 11;
        const CLONE_PIDFD = 1 << 12;
        const CLONE_PTRACE = 1 << 13;
        const CLONE_VFORK = 1 << 14;
        const CLONE_PARENT = 1 << 15;
        const CLONE_THREAD = 1 << 16;
        const CLONE_NEWNS = 1 << 17;
        const CLONE_SYSVSEM = 1 << 18;
        const CLONE_SETTLS = 1 << 19;
        const CLONE_PARENT_SETTID = 1 << 20;
        const CLONE_CHILD_CLEARTID = 1 << 21;
        const CLONE_DETACHED = 1 << 22;
        const CLONE_UNTRACED = 1 << 23;
        const CLONE_CHILD_SETTID = 1 << 24;
        const CLONE_NEWCGROUP = 1 << 25;
        const CLONE_NEWUTS = 1 << 26;
        const CLONE_NEWIPC = 1 << 27;
        const CLONE_NEWUSER = 1 << 28;
        const CLONE_NEWPID = 1 << 29;
        const CLONE_NEWNET = 1 << 30;
        const CLONE_IO = 1 << 31;
    }
}

bitflags! {
    pub struct WaitOptions: u32 {
        const WNOHANG = 1;
        const WUNTRACED = 1 << 1;
        const WCONTINUED = 1 << 3;
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, TryFromPrimitive)]
#[repr(u32)]
pub enum RlimitCmd {
    RLIMIT_CPU = 0,
    RLIMIT_FSIZE = 1,
    RLIMIT_DATA = 2,
    RLIMIT_STACK = 3,
    RLIMIT_CORE = 4,
    RLIMIT_RSS = 5,
    RLIMIT_NPROC = 6,
    RLIMIT_NOFILE = 7,
    RLIMIT_MEMLOCK = 8,
    RLIMIT_AS = 9,
    RLIMIT_LOCKS = 10,
    RLIMIT_SIGPENDING = 11,
    RLIMIT_MSGQUEUE = 12,
    RLIMIT_NICE = 13,
    RLIMIT_RTPRIO = 14,
    RLIMIT_RTTIME = 15,
}

#[derive(Copy, Clone, AsBytes)]
#[repr(C)]
pub struct Rlimit {
    pub rlim_cur: usize,
    pub rlim_max: usize,
}

pub const RUSAGE_SELF: i32 = 0;
pub const RUSAGE_THREAD: i32 = 1;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, AsBytes)]
pub struct RUsage {
    /// user CPU time used
    pub ru_utime: TimeVal,
    /// system CPU time used
    pub ru_stime: TimeVal,
    /// maximum resident set size
    pub ru_maxrss: usize,
    /// integral shared memory size
    pub ru_ixrss: usize,
    /// integral unshared data size
    pub ru_idrss: usize,
    /// integral unshared stack size
    pub ru_isrss: usize,
    /// page reclaims (soft page faults)
    pub ru_minflt: usize,
    /// page faults (hard page faults)
    pub ru_majflt: usize,
    /// swaps
    pub ru_nswap: usize,
    /// block input operations
    pub ru_inblock: usize,
    /// block output operations
    pub ru_oublock: usize,
    /// IPC messages sent
    pub ru_msgsnd: usize,
    /// IPC messages received
    pub ru_msgrcv: usize,
    /// signals received
    pub ru_nsignals: usize,
    /// voluntary context switches
    pub ru_nvcsw: usize,
    /// involuntary context switches
    pub ru_nivcsw: usize,
}
