use core::time::Duration;
use num_enum::TryFromPrimitive;
use zerocopy::{AsBytes, FromBytes, FromZeroes};
use crate::result::{Errno, SyscallResult};

pub const UTIME_NOW: i64 = 1073741823;
pub const UTIME_OMIT: i64 = 1073741822;

pub const CLOCK_REALTIME: usize = 0;
pub const CLOCK_MONOTONIC: usize = 1;
pub const CLOCK_PROCESS_CPUTIME_ID: usize = 2;
pub const CLOCK_THREAD_CPUTIME_ID: usize = 3;
pub const CLOCK_MONOTONIC_RAW: usize = 4;
pub const CLOCK_REALTIME_COARSE: usize = 5;
pub const CLOCK_MONOTONIC_COARSE: usize = 6;
pub const CLOCK_BOOTTIME: usize = 7;

pub const TIMER_ABSTIME: i32 = 1;

#[derive(Copy, Clone, Debug, TryFromPrimitive)]
#[repr(i32)]
pub enum ITimerType {
    Real = 0,
    Virtual = 1,
    Prof = 2,
}

#[derive(Copy, Clone, Debug, Default, AsBytes, FromZeroes, FromBytes)]
#[repr(C)]
pub struct TimeSpec {
    pub sec: i64,
    pub nsec: i64,
}

#[derive(Copy, Clone, Debug, Default, AsBytes, FromZeroes, FromBytes)]
#[repr(C)]
pub struct TimeVal {
    pub sec: i64,
    pub usec: i64,
}

#[derive(Clone, Debug, Default, AsBytes, FromZeroes, FromBytes)]
#[repr(C)]
pub struct ITimerVal {
    pub interval: TimeVal,
    pub value: TimeVal,
}

#[derive(Copy, Clone, Debug, Default, AsBytes, FromZeroes, FromBytes)]
#[repr(C)]
pub struct TimeZone {
    pub minuteswest: i32,
    pub dsttime: i32,
}

impl TimeSpec {
    pub fn new(sec: i64, nsec: i64) -> Self {
        Self { sec, nsec }
    }

    pub fn check_forward(&self) -> SyscallResult {
        let ok = self.sec >= 0 && (0..1_000_000_000).contains(&self.nsec);
        ok.then_some(()).ok_or(Errno::EINVAL)
    }
}

impl TimeVal {
    pub fn new(sec: i64, usec: i64) -> Self {
        Self { sec, usec }
    }
}

impl From<Duration> for TimeSpec {
    fn from(d: Duration) -> Self {
        let sec = d.as_secs() as i64;
        let nsec = d.subsec_nanos() as i64;
        Self { sec, nsec }
    }
}

impl From<Duration> for TimeVal {
    fn from(d: Duration) -> Self {
        let sec = d.as_secs() as i64;
        let usec = d.subsec_micros() as i64;
        Self { sec, usec }
    }
}

impl From<TimeSpec> for Duration {
    fn from(ts: TimeSpec) -> Self {
        Duration::new(ts.sec as u64, ts.nsec as u32)
    }
}

impl From<TimeVal> for Duration {
    fn from(tv: TimeVal) -> Self {
        Duration::new(tv.sec as u64, (tv.usec * 1000) as u32)
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, AsBytes, FromZeroes, FromBytes)]
pub struct TMS {
    pub tms_utime: u64,
    pub tms_stime: u64,
    pub tms_cutime: u64,
    pub tms_cstime: u64,
}

#[repr(C)]
#[derive(Copy, Clone, AsBytes, FromZeroes, FromBytes)]
pub struct Timex {
    /// Mode selector
    pub modes: i32,
    _pad1: i32,
    /// Time offset (nanoseconds)
    pub offset: usize,
    /// Frequency offset
    pub freq: usize,
    /// Maximum error (microseconds)
    pub maxerror: usize,
    /// Estimated error (microseconds)
    pub esterror: usize,
    /// Clock command/status
    pub status: i32,
    _pad2: i32,
    /// PLL (phase-locked loop) time constant
    pub constant: usize,
    /// Clock precision (microseconds, read-only)
    pub precision: usize,
    /// Clock frequency tolerance (read-only)
    pub tolerance: usize,
    /// Current time (read-only, except for [ADJ_SETOFFSET]);
    /// upon return, time.tv_usec contains nanoseconds,
    /// if [STA_NANO] status flag is set, otherwise microseconds
    pub time: TimeVal,
    /// Microseconds between clock ticks
    pub tick: usize,
    /// PPS (pulse per second) frequency (read-only)
    pub ppsfreq: usize,
    /// PPS jitter (read-only); nanoseconds,
    /// if [STA_NANO] status flag is set, otherwise microseconds
    pub jitter: usize,
    /// PPS interval duration (seconds, read-only)
    pub shift: i32,
    _pad3: i32,
    /// PPS stability (read-only)
    pub stabil: usize,
    /// PPS count of jitter limit exceeded events (read-only)
    pub jitcnt: usize,
    /// PPS count of calibration intervals (read-only)
    pub calcnt: usize,
    /// PPS count of calibration errors (read-only)
    pub errcnt: usize,
    /// PPS count of stability limit exceeded events (read-only)
    pub stbcnt: usize,
    /// TAI offset, as set by previous ADJ_TAI operation (seconds, read-only)
    pub tai: i32,
    _pad4: i32,
}

#[repr(i32)]
#[derive(TryFromPrimitive)]
pub enum SchedPolicy {
    SchedFifo = 1,
    SchedRr = 2,
    SchedOther = 0,
    SchedBatch = 3,
    SchedIdle = 5,
    SchedDeadline = 6,
}
