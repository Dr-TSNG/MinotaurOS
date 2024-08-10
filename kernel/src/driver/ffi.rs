use bitflags::bitflags;

pub const DEV_CHAR_TTY: u32 = 4;

pub const DEV_BLOCK_SCSI: u32 = 8;

pub const fn make_dev(major: u32, minor: u32) -> u64 {
    ((major as u64) << 8) | (minor as u64)
}

pub const fn sep_dev(dev: u64) -> (u32, u32) {
    let major = (dev >> 8) as u32;
    let minor = (dev & 0xff) as u32;
    (major, minor)
}

bitflags! {
    pub struct RandomFlags: u32 {
        const GRND_RANDOM   = 1 << 0;
        const GRND_NONBLOCK = 1 << 1;
        const GRND_INSECURE = 1 << 2;
    }
}
