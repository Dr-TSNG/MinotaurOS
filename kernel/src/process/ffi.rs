use bitflags::bitflags;
use num_enum::TryFromPrimitive;
use zerocopy::{AsBytes, FromBytes, FromZeroes};
use crate::sched::ffi::TimeVal;

bitflags! {
    #[derive(Copy, Clone, Debug)]
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
    #[derive(Debug)]
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

#[derive(Clone, AsBytes, FromZeroes, FromBytes)]
#[repr(C)]
pub struct Rlimit {
    pub rlim_cur: usize,
    pub rlim_max: usize,
}

impl Rlimit {
    pub const fn new(cur: usize, max: usize) -> Self {
        Self { rlim_cur: cur, rlim_max: max }
    }
}

pub const RUSAGE_SELF: i32 = 0;
pub const RUSAGE_THREAD: i32 = 1;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, AsBytes, FromZeroes, FromBytes)]
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

#[repr(C)]
#[derive(Copy, Clone, AsBytes, FromZeroes, FromBytes)]
pub struct CpuSet {
    /// cpu set
    pub set: usize,
    /// for padding
    pub dummy: [usize; 15],
}

impl CpuSet {
    pub fn new(cpus: usize) -> Self {
        Self {
            set: (1 << cpus - 1),
            dummy: [0; 15],
        }
    }
}

bitflags! {
    #[repr(transparent)]
    #[derive(Eq, PartialEq, Copy, Clone, Default)]
    pub struct CapSet: u64 {
        const CAP_CHOWN              = 1 << 0;
        const CAP_DAC_OVERRIDE       = 1 << 1;
        const CAP_DAC_READ_SEARCH    = 1 << 2;
        const CAP_FOWNER             = 1 << 3;
        const CAP_FSETID             = 1 << 4;
        const CAP_KILL               = 1 << 5;
        const CAP_SETGID             = 1 << 6;
        const CAP_SETUID             = 1 << 7;
        const CAP_SETPCAP            = 1 << 8;
        const CAP_LINUX_IMMUTABLE    = 1 << 9;
        const CAP_NET_BIND_SERVICE   = 1 << 10;
        const CAP_NET_BROADCAST      = 1 << 11;
        const CAP_NET_ADMIN          = 1 << 12;
        const CAP_NET_RAW            = 1 << 13;
        const CAP_IPC_LOCK           = 1 << 14;
        const CAP_IPC_OWNER          = 1 << 15;
        const CAP_SYS_MODULE         = 1 << 16;
        const CAP_SYS_RAWIO          = 1 << 17;
        const CAP_SYS_CHROOT         = 1 << 18;
        const CAP_SYS_PTRACE         = 1 << 19;
        const CAP_SYS_PACCT          = 1 << 20;
        const CAP_SYS_ADMIN          = 1 << 21;
        const CAP_SYS_BOOT           = 1 << 22;
        const CAP_SYS_NICE           = 1 << 23;
        const CAP_SYS_RESOURCE       = 1 << 24;
        const CAP_SYS_TIME           = 1 << 25;
        const CAP_SYS_TTY_CONFIG     = 1 << 26;
        const CAP_MKNOD              = 1 << 27;
        const CAP_LEASE              = 1 << 28;
        const CAP_AUDIT_WRITE        = 1 << 29;
        const CAP_AUDIT_CONTROL      = 1 << 30;
        const CAP_SETFCAP            = 1 << 31;
        const CAP_MAC_OVERRIDE       = 1 << 32;
        const CAP_MAC_ADMIN          = 1 << 33;
        const CAP_SYSLOG             = 1 << 34;
        const CAP_WAKE_ALARM         = 1 << 35;
        const CAP_BLOCK_SUSPEND      = 1 << 36;
        const CAP_AUDIT_READ         = 1 << 37;
        const CAP_PERFMON            = 1 << 38;
        const CAP_BPF                = 1 << 39;
        const CAP_CHECKPOINT_RESTORE = 1 << 40;
    }
}

impl CapSet {
    pub fn from_id(id: usize) -> Option<Self> {
        let bits = 1u64.checked_shl(id.try_into().ok()?)?;
        Self::from_bits(bits)
    }
}

pub const LINUX_CAPABILITY_VERSION_1: u32 = 0x19980330;
pub const LINUX_CAPABILITY_VERSION_2: u32 = 0x20071026;
pub const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

#[repr(C)]
#[derive(AsBytes, FromZeroes, FromBytes)]
pub struct CapUserHeader {
    pub version: u32,
    pub pid: i32,
}

#[repr(C)]
#[derive(AsBytes, FromZeroes, FromBytes)]
pub struct CapUserData {
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
}

pub fn mk_kernel_cap(low: u32, high: u32) -> CapSet {
    CapSet::from_bits_truncate((high as u64) << 32 | low as u64)
}

pub fn mk_cap_user_data(cap: CapSet, low: &mut u32, high: &mut u32) {
    *low = cap.bits() as u32;
    *high = (cap.bits() >> 32) as u32;
}

#[repr(i32)]
#[derive(TryFromPrimitive)]
#[allow(non_camel_case_types)]
pub enum PrctlOption {
    PR_CAPBSET_READ = 23,
    PR_CAPBSET_DROP = 24,
}
