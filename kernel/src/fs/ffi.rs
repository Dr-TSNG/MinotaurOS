use bitflags::bitflags;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct TimeSpec {
    pub sec: usize,
    pub nsec: usize,
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
