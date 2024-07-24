use alloc::vec::Vec;
use core::fmt::Display;
use core::mem::size_of;
use bitflags::bitflags;
use lazy_static::lazy_static;
use num_enum::TryFromPrimitive;
use zerocopy::{AsBytes, FromBytes, FromZeroes};
use crate::fs::fd::FdNum;
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
        const O_STATUS    = Self::O_APPEND.bits() | Self::O_ASYNC.bits() | Self::O_DIRECT.bits() | Self::O_NOATIME.bits() | Self::O_NONBLOCK.bits();
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
    pub struct RenameFlags: u32 {
        /// Default behavior.
        const RENAME_DEFAULT = 0;
        /// Don't overwrite newpath of the rename. Return an error if newpath already exists.
        const RENAME_NOREPLACE = 1 << 0;
        /// Atomically exchange oldpath and newpath.
        const RENAME_EXCHANGE = 1 << 1;
        /// This operation makes sense only for overlay/union filesystem implementations.
        const RENAME_WHITEOUT = 1 << 2;
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

impl Display for VfsFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut flags = Vec::new();
        if self.contains(VfsFlags::ST_RDONLY) {
            flags.push("ro");
        }
        if self.contains(VfsFlags::ST_NOSUID) {
            flags.push("nosuid");
        }
        if self.contains(VfsFlags::ST_NODEV) {
            flags.push("nodev");
        }
        if self.contains(VfsFlags::ST_NOEXEC) {
            flags.push("noexec");
        }
        if self.contains(VfsFlags::ST_SYNCHRONOUS) {
            flags.push("sync");
        }
        if self.contains(VfsFlags::ST_MANDLOCK) {
            flags.push("mand");
        }
        if self.contains(VfsFlags::ST_WRITE) {
            flags.push("rw");
        }
        if self.contains(VfsFlags::ST_APPEND) {
            flags.push("append");
        }
        if self.contains(VfsFlags::ST_IMMUTABLE) {
            flags.push("immutable");
        }
        if self.contains(VfsFlags::ST_NOATIME) {
            flags.push("noatime");
        }
        if self.contains(VfsFlags::ST_NODIRATIME) {
            flags.push("nodiratime");
        }
        if self.contains(VfsFlags::ST_RELATIME) {
            flags.push("relatime");
        }
        if self.contains(VfsFlags::ST_NOSYMFOLLOW) {
            flags.push("nosymfollow");
        }
        write!(f, "{}", flags.join(","))
    }
}

#[allow(non_camel_case_types)]
#[derive(PartialEq, Debug, Clone, Copy, TryFromPrimitive)]
#[repr(usize)]
pub enum FcntlCmd {
    F_DUPFD = 0,
    F_GETFD = 1,
    F_SETFD = 2,
    F_GETFL = 3,
    F_SETFL = 4,
    F_DUPFD_CLOEXEC = 1030,
}

/// Inode 类型
#[derive(TryFromPrimitive, PartialEq, Debug, Clone, Copy)]
#[repr(u16)]
pub enum InodeMode {
    /// FIFO
    IFIFO = 0x1000,
    /// 字符设备
    IFCHR = 0x2000,
    /// 目录
    IFDIR = 0x4000,
    /// 块设备
    IFBLK = 0x6000,
    /// 一般文件
    IFREG = 0x8000,
    /// 符号链接
    IFLNK = 0xA000,
    /// socket
    IFSOCK = 0xC000,
}

pub const AT_FDCWD: i32 = -100;
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
pub const AT_REMOVEDIR: u32 = 0x200;

pub const PATH_MAX: usize = 260;
pub const MAX_NAME_LEN: usize = 253;
pub const MAX_DIRENT_SIZE: usize = size_of::<LinuxDirent>();

#[repr(C)]
pub struct IoVec {
    pub base: usize,
    pub len: usize,
}

#[derive(AsBytes, FromZeroes)]
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
            InodeMode::IFIFO => DirentType::DT_FIFO,
            InodeMode::IFCHR => DirentType::DT_CHR,
            InodeMode::IFDIR => DirentType::DT_DIR,
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
#[derive(Default, AsBytes, FromZeroes, FromBytes)]
pub struct KernelStat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    __pad1: usize,
    pub st_size: u64,
    pub st_blksize: u32,
    __pad2: u32,
    pub st_blocks: u64,
    pub st_atim: TimeSpec,
    pub st_mtim: TimeSpec,
    pub st_ctim: TimeSpec,
}

#[repr(C)]
#[derive(Default, AsBytes, FromZeroes, FromBytes)]
pub struct KernelStatfs {
    pub f_type: u64,
    pub f_bsize: u64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_fsid: u64,
    pub f_namelen: u64,
    pub f_frsize: u64,
    pub f_flags: u64,
    pub f_spare: [u64; 4],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, AsBytes, FromZeroes, FromBytes)]
pub struct PollFd {
    /// Fd
    pub fd: FdNum,
    /// Requested events
    pub events: PollEvents,
    /// Returned events
    pub revents: PollEvents,
}

bitflags! {
    /// Poll events
    #[repr(transparent)]
    #[derive(AsBytes, FromZeroes, FromBytes)]
    pub struct PollEvents: i16 {
        /// There is data to read
        const POLLIN = 1 << 0;
        /// Execption about fd
        const POLLPRI = 1 << 1;
        /// There is data to write
        const POLLOUT = 1 << 2;
        /// Error condition
        const POLLERR = 1 << 3;
        /// Hang up
        const POLLHUP = 1 << 4;
        /// Invalid request: fd not open
        const POLLNVAL = 1 << 5;
    }
}


pub const FD_SET_SIZE: usize = 1024;
pub const FD_SET_LEN: usize = FD_SET_SIZE / (8 * size_of::<usize>());

#[repr(C)]
#[derive(Debug, Copy, Clone, AsBytes, FromZeroes, FromBytes)]
pub struct FdSet {
    pub fds_bits: [usize; FD_SET_LEN],
}

impl FdSet {
    pub fn mark_fd(&mut self, fd: usize) {
        if fd >= FD_SET_SIZE {
            return;
        }
        let offset = fd % FD_SET_LEN;
        self.fds_bits[fd / FD_SET_LEN] |= 1 << offset;
    }
}
