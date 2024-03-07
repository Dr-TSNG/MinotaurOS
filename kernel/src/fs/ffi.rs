use core::time::Duration;
use bitflags::bitflags;
use lazy_static::lazy_static;
use zerocopy::{AsBytes, FromZeroes};

#[derive(Copy, Clone, Debug, Default, AsBytes)]
#[repr(C)]
pub struct TimeSpec {
    pub sec: i64,
    pub nsec: i64,
}

impl TimeSpec {
    pub fn new(sec: i64, nsec: i64) -> Self {
        Self { sec, nsec }
    }
}

impl From<Duration> for TimeSpec {
    fn from(d: Duration) -> Self {
        let sec = d.as_secs() as i64;
        let nsec = d.subsec_nanos() as i64;
        Self { sec, nsec }
    }
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

pub const PATH_MAX: usize = 260;

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
