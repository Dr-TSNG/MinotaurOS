use num_enum::TryFromPrimitive;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

#[allow(non_camel_case_types)]
#[derive(Debug, TryFromPrimitive)]
#[repr(i32)]
pub enum SyslogCmd {
    SYSLOG_ACTION_CLOSE = 0,
    SYSLOG_ACTION_OPEN = 1,
    SYSLOG_ACTION_READ = 2,
    SYSLOG_ACTION_READ_ALL = 3,
    SYSLOG_ACTION_READ_CLEAR = 4,
    SYSLOG_ACTION_CLEAR = 5,
    SYSLOG_ACTION_CONSOLE_OFF = 6,
    SYSLOG_ACTION_CONSOLE_ON = 7,
    SYSLOG_ACTION_CONSOLE_LEVEL = 8,
    SYSLOG_ACTION_SIZE_UNREAD = 9,
    SYSLOG_ACTION_SIZE_BUFFER = 10,
}

#[derive(Default, AsBytes, FromZeroes, FromBytes)]
#[repr(C)]
pub struct SysInfo {
    /// Seconds since boot
    pub uptime: isize,
    /// 1, 5, and 15 minute load averages
    pub loads: [usize; 3],
    /// Total usable main memory size
    pub totalram: usize,
    /// Available memory size
    pub freeram: usize,
    /// Amount of shared memory
    pub sharedram: usize,
    /// Memory used by buffers
    pub bufferram: usize,
    /// Total swap space size
    pub totalswap: usize,
    /// swap space still available
    pub freeswap: usize,
    /// Number of current processes
    pub procs: u16,
    /// Padding
    __pad1: [u8; 6],
    /// Total high memory size
    pub totalhigh: usize,
    /// Available high memory size
    pub freehigh: usize,
    /// Memory unit size in bytes
    pub mem_uint: u32,
    /// Padding
    __pad2: [u8; 4],
}
