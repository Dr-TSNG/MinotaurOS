use core::time::Duration;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

#[derive(Copy, Clone, Debug, Default, AsBytes, FromZeroes, FromBytes)]
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

impl From<TimeSpec> for Duration {
    fn from(ts: TimeSpec) -> Self {
        Duration::new(ts.sec as u64, ts.nsec as u32)
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
