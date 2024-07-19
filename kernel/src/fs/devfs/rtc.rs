use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::{Arc, Weak};
use core::mem::size_of;
use core::sync::atomic::Ordering;
use async_trait::async_trait;
use log::debug;
use riscv::register::Permission::R;
use zerocopy::AsBytes;
use crate::arch::VirtAddr;
use crate::fs::devfs::DevFileSystem;
use crate::fs::ffi::{InodeMode, OpenFlags, PollFd};
use crate::fs::file::File;
use crate::fs::file_system::FileSystem;
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::processor::current_process;
use crate::result::{Errno, SyscallResult};
use crate::sched::ffi::TimeSpec;
pub struct RtcInode(InodeMeta, Weak<DevFileSystem>);

impl RtcInode {
    pub fn new(fs: Arc<DevFileSystem>, parent: Arc<dyn Inode>) -> Arc<Self> {
        Arc::new(Self(InodeMeta::new(
            fs.ino_pool.fetch_add(1, Ordering::Relaxed),
            0,
            InodeMode::IFCHR,
            "rtc".to_string(),
            "/rtc".to_string(),
            Some(parent),
            None,
            TimeSpec::default(),
            TimeSpec::default(),
            TimeSpec::default(),
            512,
        ), Arc::downgrade(&fs)))
    }
}

#[async_trait]
impl InodeInternal for RtcInode {
    async fn read_direct(&self, buf: &mut [u8], _: isize) -> SyscallResult<isize> {
        debug!("read /dev/rtc");
        buf.fill(0);
        Ok(buf.len() as isize)
    }

    async fn write_direct(&self, _: &[u8], _: isize) -> SyscallResult<isize> {
        Ok(0)
    }
}

impl Inode for RtcInode {
    fn metadata(&self) -> &InodeMeta {
        &self.0
    }

    fn file_system(&self) -> Weak<dyn FileSystem> {
        self.1.clone()
    }

    fn ioctl(&self, request: usize, value: usize, arg3: usize, arg4: usize, arg5: usize) -> SyscallResult<i32> {
        let value = current_process().inner.lock().addr_space
            .user_slice_w(VirtAddr(value), size_of::<RtcTime>())?;
        let rtc=RtcTime::new();
        value.copy_from_slice(rtc.as_bytes());
        Ok(0)
    }
}

#[repr(C)]
#[derive(AsBytes,Debug)]
pub struct RtcTime {
    tm_sec: i32,
    tm_min: i32,
    tm_hour: i32,
    tm_mday: i32,
    tm_mon: i32,
    tm_year: i32,

}
impl RtcTime{
    fn new() -> Self {
        RtcTime { tm_sec:0, tm_min: 0, tm_hour: 0, tm_mday: 0, tm_mon: 0, tm_year: 0}
    }
}