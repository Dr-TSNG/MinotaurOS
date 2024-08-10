use alloc::ffi::CString;
use alloc::vec::Vec;
use core::fmt::{Display, Formatter};
use core::mem::{offset_of, size_of};
use core::ptr::addr_of;
use bitflags::bitflags;
use lazy_static::lazy_static;
use num_enum::TryFromPrimitive;
use zerocopy::{AsBytes, FromBytes, FromZeroes};
use crate::fs::fd::FdNum;
use crate::sched::ffi::TimeSpec;

bitflags! {
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
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
    #[derive(Debug, Eq, PartialEq)]
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
    #[derive(Clone)]
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
        /// Alter flags of a mounted FS
        const MS_REMOUNT     = 1 << 5;
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
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
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
    F_SETPIPE_SZ = 1031,
    F_GETPIPE_SZ = 1032,
}

bitflags! {
    #[derive(Copy, Clone, Eq, PartialEq)]
    pub struct InodeMode: u32 {
        const S_IFIFO  = 0x1000;
        const S_IFCHR  = 0x2000;
        const S_IFDIR  = 0x4000;
        const S_IFBLK  = 0x6000;
        const S_IFREG  = 0x8000;
        const S_IFLNK  = 0xA000;
        const S_IFSOCK = 0xC000;
        const S_IFMT   = 0xF000;
        const S_ISUID  = 0x0800;
        const S_ISGID  = 0x0400;
        const S_ISVTX  = 0x0200;
        const S_IRUSR  = 0x0100;
        const S_IWUSR  = 0x0080;
        const S_IXUSR  = 0x0040;
        const S_IRWXU  = Self::S_IRUSR.bits() | Self::S_IWUSR.bits() | Self::S_IXUSR.bits();
        const S_IRGRP  = 0x0020;
        const S_IWGRP  = 0x0010;
        const S_IXGRP  = 0x0008;
        const S_IRWXG  = Self::S_IRGRP.bits() | Self::S_IWGRP.bits() | Self::S_IXGRP.bits();
        const S_IROTH  = 0x0004;
        const S_IWOTH  = 0x0002;
        const S_IXOTH  = 0x0001;
        const S_IRWXO  = Self::S_IROTH.bits() | Self::S_IWOTH.bits() | Self::S_IXOTH.bits();
        const S_ACCESS = Self::S_IRWXU.bits() | Self::S_IRWXG.bits() | Self::S_IRWXO.bits();
        const S_MISC   = Self::S_ACCESS.bits() | Self::S_ISUID.bits() | Self::S_ISGID.bits() | Self::S_ISVTX.bits();
    }
}

impl Display for InodeMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self.file_type() {
            InodeMode::S_IFIFO => write!(f, "c")?,
            InodeMode::S_IFCHR => write!(f, "c")?,
            InodeMode::S_IFDIR => write!(f, "d")?,
            InodeMode::S_IFBLK => write!(f, "b")?,
            InodeMode::S_IFREG => write!(f, "f")?,
            InodeMode::S_IFLNK => write!(f, "s")?,
            InodeMode::S_IFSOCK => write!(f, "c")?,
            _ => write!(f, "unknown")?,
        }
        let mut rwx = |bits: u32| {
            let s = match bits {
                0 => "---",
                1 => "--x",
                2 => "-w-",
                3 => "-wx",
                4 => "r--",
                5 => "r-x",
                6 => "rw-",
                7 => "rwx",
                _ => unreachable!(),
            };
            f.write_str(s)
        };
        rwx((self.bits() & 0o700) >> 6)?;
        rwx((self.bits() & 0o070) >> 3)?;
        rwx(self.bits() & 0o007)?;
        Ok(())
    }
}

impl InodeMode {
    pub fn def_dir() -> Self {
        InodeMode::S_IFDIR | InodeMode::from_bits(0o777).unwrap()
    }

    pub fn def_file() -> Self {
        InodeMode::S_IFREG | InodeMode::from_bits(0o666).unwrap()
    }

    pub fn def_lnk() -> Self {
        InodeMode::S_IFLNK | InodeMode::from_bits(0o777).unwrap()
    }

    pub fn from_bits_access(bits: u32) -> Self {
        Self::from_bits_retain(bits) & InodeMode::S_ACCESS
    }

    pub fn from_bits_misc(bits: u32) -> Self {
        Self::from_bits_retain(bits) & InodeMode::S_MISC
    }

    pub fn file_type(&self) -> InodeMode {
        *self & InodeMode::S_IFMT
    }

    pub fn is_dir(&self) -> bool {
        self.file_type() == InodeMode::S_IFDIR
    }

    pub fn is_reg(&self) -> bool {
        self.file_type() == InodeMode::S_IFREG
    }

    pub fn is_lnk(&self) -> bool {
        self.file_type() == InodeMode::S_IFLNK
    }
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
        match value.file_type() {
            InodeMode::S_IFIFO => DirentType::DT_FIFO,
            InodeMode::S_IFCHR => DirentType::DT_CHR,
            InodeMode::S_IFDIR => DirentType::DT_DIR,
            InodeMode::S_IFBLK => DirentType::DT_BLK,
            InodeMode::S_IFREG => DirentType::DT_REG,
            InodeMode::S_IFLNK => DirentType::DT_LNK,
            InodeMode::S_IFSOCK => DirentType::DT_SOCK,
            _ => DirentType::DT_UNKNOWN,
        }
    }
}

const SYSNAME: &str = "Linux";
const NODENAME: &str = "Minotaur";
const RELEASE: &str = "5.19.0-42-generic";
const VERSION: &str = "#43~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Fri Apr 21 16:51:08 UTC 2";
const MACHINE: &str = "riscv64";
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
#[derive(Copy, Clone, Debug, AsBytes, FromZeroes, FromBytes)]
pub struct PollFd {
    /// Fd
    pub fd: FdNum,
    /// Requested events
    pub events: PollEvents,
    /// Returned events
    pub revents: PollEvents,
}

/// Poll events
#[repr(transparent)]
#[derive(Copy, Clone, Debug, AsBytes, FromZeroes, FromBytes)]
pub struct PollEvents(i16);

bitflags! {
    impl PollEvents: i16 {
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

bitflags! {
    pub struct AccessMode: u32 {
        const F_OK = 0;
        const R_OK = 4;
        const W_OK = 2;
        const X_OK = 1;
    }
}

impl AccessMode {
    pub fn new(read: bool, write: bool, execute: bool) -> Self {
        let mut mode = AccessMode::F_OK;
        if read {
            mode |= AccessMode::R_OK;
        }
        if write {
            mode |= AccessMode::W_OK;
        }
        if execute {
            mode |= AccessMode::X_OK;
        }
        mode
    }
}

// cookie 是事件唯一标识符号，用于将相关事件配对。
// 移动事件: 当一个文件或目录被移动时，会生成一对事件：IN_MOVED_FROM 和 IN_MOVED_TO。
// 事件 cookie 可以将这两个事件联系起来，表明它们是同一次移动操作的两部分。
#[repr(C)]
#[derive(Clone)]
pub struct InotifyEvent {
    /// 监视描述符
    pub wd: i32,
    /// 事件掩码
    pub mask: u32,
    /// 事件 cookie
    pub cookie: u32,
    // 文件名长度
    pub len: u32,
    // 文件名（变长）
    pub name: CString,
}

impl InotifyEvent {
    pub fn as_bytes(&self) -> &[u8] {
        let len = offset_of!(Self, name) + self.name.as_bytes().len();
        unsafe { core::slice::from_raw_parts(addr_of!(self) as *const u8, len) }
    }
}

bitflags! {
    pub struct InotifyMask: u32 {
        const IN_ACCESS        = 0x00000001; // 文件被访问（读取）
        const IN_MODIFY        = 0x00000002; // 文件被修改
        const IN_ATTRIB        = 0x00000004; // 文件属性被修改
        const IN_CLOSE_WRITE   = 0x00000008; // 以可写方式打开的文件被关闭
        const IN_CLOSE_NOWRITE = 0x00000010; // 以不可写方式打开的文件被关闭
        const IN_OPEN          = 0x00000020; // 文件被打开
        const IN_MOVED_FROM    = 0x00000040; // 文件从监视的目录中被移走
        const IN_MOVED_TO      = 0x00000080; // 文件被移动到监视的目录中
        const IN_CREATE        = 0x00000100; // 监视的目录中创建了文件
        const IN_DELETE        = 0x00000200; // 监视的目录中删除了文件
        const IN_DELETE_SELF   = 0x00000400; // 被监视的文件自身被删除
        const IN_MOVE_SELF     = 0x00000800; // 被监视的文件自身被移动
        const IN_UNMOUNT       = 0x00002000; // 文件系统被卸载
        const IN_Q_OVERFLOW    = 0x00004000; // 事件队列溢出
        const IN_IGNORED       = 0x00008000; // 监视项被忽略
        const IN_ONLYDIR       = 0x01000000; // 仅监视目录
        const IN_DONT_FOLLOW   = 0x02000000; // 不跟随符号链接
        const IN_EXCL_UNLINK   = 0x04000000; // 不生成对已被删除对象的事件
        const IN_MASK_ADD      = 0x20000000; // 将新的事件掩码加入已存在的掩码中
        const IN_ISDIR         = 0x40000000; // 事件发生在目录中
    }
}
