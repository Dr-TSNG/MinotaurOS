use core::time::Duration;
use num_enum::TryFromPrimitive;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

pub const UTIME_NOW: i64 = 1073741823;
pub const UTIME_OMIT: i64 = 1073741822;

pub const CLOCK_REALTIME: usize = 0;
pub const CLOCK_MONOTONIC: usize = 1;
pub const CLOCK_PROCESS_CPUTIME_ID: usize = 2;
pub const CLOCK_THREAD_CPUTIME_ID: usize = 3;

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

impl TimeSpec {
    pub fn new(sec: i64, nsec: i64) -> Self {
        Self { sec, nsec }
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
        Duration::new(tv.sec as u64, tv.usec as u32 * 1000)
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, AsBytes)]
pub struct TMS {
    pub tms_utime: u64,
    pub tms_stime: u64,
    pub tms_cutime: u64,
    pub tms_cstime: u64,
}
