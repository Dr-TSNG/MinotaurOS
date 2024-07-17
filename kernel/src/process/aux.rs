#![allow(unused)]

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Aux {
    pub a_type: usize,
    pub a_value: usize,
}

impl Aux {
    pub const fn new(a_type: usize, a_value: usize) -> Self {
        Self { a_type, a_value }
    }
}

/// End of vector
pub const AT_NULL: usize = 0;
/// Entry should be ignored
pub const AT_IGNORE: usize = 1;
/// File descriptor of program
pub const AT_EXECFD: usize = 2;
/// Program headers for program
pub const AT_PHDR: usize = 3;
/// Size of program header entry
pub const AT_PHENT: usize = 4;
/// Number of program headers
pub const AT_PHNUM: usize = 5;
/// System page size
pub const AT_PAGESZ: usize = 6;
/// Base address of interpreter
pub const AT_BASE: usize = 7;
/// Flags
pub const AT_FLAGS: usize = 8;
/// Entry point of program
pub const AT_ENTRY: usize = 9;
/// Program is not ELF
pub const AT_NOTELF: usize = 10;
/// Real uid
pub const AT_UID: usize = 11;
/// Effective uid
pub const AT_EUID: usize = 12;
/// Real gid
pub const AT_GID: usize = 13;
/// Effective gid
pub const AT_EGID: usize = 14;
/// String identifying CPU for optimizations
pub const AT_PLATFORM: usize = 15;
/// Arch dependent hints at CPU capabilities
pub const AT_HWCAP: usize = 16;
/// Frequency at which times() increments
pub const AT_CLKTCK: usize = 17;
/// Secure mode boolean
pub const AT_SECURE: usize = 23;
/// String identifying real platform, may differ from AT_PLATFORM.
pub const AT_BASE_PLATFORM: usize = 24;
/// Address of 16 random bytes
pub const AT_RANDOM: usize = 25;
/// Extension of AT_HWCAP
pub const AT_HWCAP2: usize = 26;
/// Filename of program
pub const AT_EXECFN: usize = 31;
/// Pointer to the global system page used for system calls and other nice things.
pub const AT_SYSINFO: usize = 32;
pub const AT_SYSINFO_EHDR: usize = 33;
