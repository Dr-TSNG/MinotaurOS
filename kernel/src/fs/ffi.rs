use core::mem::size_of;
use bitflags::bitflags;
use lazy_static::lazy_static;
use zerocopy::{AsBytes, FromZeroes};
use crate::sched::ffi::TimeSpec;

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

impl OpenFlags {
    pub fn readable(&self) -> bool {
        self.contains(OpenFlags::O_RDONLY) || self.contains(OpenFlags::O_RDWR)
    }

    pub fn writable(&self) -> bool {
        self.contains(OpenFlags::O_WRONLY) || self.contains(OpenFlags::O_RDWR)
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

/// Inode 类型
#[derive(PartialEq, Debug, Clone, Copy)]
#[repr(u32)]
pub enum InodeMode {
    /// socket
    IFSOCK = 0xC000,
    /// 符号链接
    IFLNK = 0xA000,
    /// 一般文件
    IFREG = 0x8000,
    /// 块设备
    IFBLK = 0x6000,
    /// 目录
    DIR = 0x4000,
    /// 字符设备
    CHR = 0x2000,
    /// FIFO
    FileFIFO = 0x1000,
}

pub const AT_FDCWD: i32 = -100;
pub const AT_REMOVEDIR: u32 = 0x200;

pub const PATH_MAX: usize = 260;
pub const MAX_NAME_LEN: usize = 256;
pub const DIRENT_SIZE: usize = size_of::<LinuxDirent>();

#[repr(C)]
pub struct IoVec {
    pub base: usize,
    pub len: usize,
}

#[repr(C)]
pub struct LinuxDirent {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
    pub d_name: [u8; MAX_NAME_LEN],
}

bitflags! {
    pub struct DirentType: u8 {
        const DT_UNKNOWN = 0;
        const DT_FIFO = 1;
        const DT_CHR = 2;
        const DT_DIR = 4;
        const DT_BLK = 6;
        const DT_REG = 8;
        const DT_LNK = 10;
        const DT_SOCK = 12;
        const DT_WHT = 14;
    }
}

impl From<InodeMode> for DirentType {
    fn from(value: InodeMode) -> Self {
        match value {
            InodeMode::FileFIFO => DirentType::DT_FIFO,
            InodeMode::CHR => DirentType::DT_CHR,
            InodeMode::DIR => DirentType::DT_DIR,
            InodeMode::IFBLK => DirentType::DT_BLK,
            InodeMode::IFREG => DirentType::DT_REG,
            InodeMode::IFLNK => DirentType::DT_LNK,
            InodeMode::IFSOCK => DirentType::DT_SOCK,
        }
    }
}

const SYSNAME: &str = "Linux";
const NODENAME: &str = "Linux";
const RELEASE: &str = "5.19.0-42-generic";
const VERSION: &str = "#43~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Fri Apr 21 16:51:08 UTC 2";
const MACHINE: &str = "RISC-V SiFive Freedom U740 SoC";
const DOMAINNAME: &str = "";

#[derive(AsBytes, FromZeroes)]
#[repr(C)]
pub struct UtsName {
    pub sysname: [u8; 65],
    pub nodename: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
    pub domainname: [u8; 65],
}

impl UtsName {
    fn new() -> Self {
        let mut this = Self::new_zeroed();
        Self::copy_bytes(&mut this.sysname, SYSNAME);
        Self::copy_bytes(&mut this.nodename, NODENAME);
        Self::copy_bytes(&mut this.release, RELEASE);
        Self::copy_bytes(&mut this.version, VERSION);
        Self::copy_bytes(&mut this.machine, MACHINE);
        Self::copy_bytes(&mut this.domainname, DOMAINNAME);
        this
    }

    fn copy_bytes(buf: &mut [u8; 65], s: &str) {
        let bytes = s.as_bytes();
        for i in 0..bytes.len() {
            buf[i] = bytes[i];
        }
    }
}

lazy_static! {
    pub static ref UTS_NAME: UtsName = UtsName::new();
}

#[repr(C)]
#[derive(Default, AsBytes)]
pub struct KernelStat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub __pad1: usize,
    pub st_size: u64,
    pub st_blksize: u32,
    pub __pad2: u32,
    pub st_blocks: u64,
    pub st_atim: TimeSpec,
    pub st_mtim: TimeSpec,
    pub st_ctim: TimeSpec,
}
