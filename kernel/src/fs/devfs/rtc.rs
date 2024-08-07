use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::Ordering;
use async_trait::async_trait;
use zerocopy::{AsBytes, FromBytes, FromZeroes};
use crate::fs::devfs::DevFileSystem;
use crate::fs::ffi::InodeMode;
use crate::fs::file_system::FileSystem;
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::mm::protect::user_transmute_w;
use crate::result::{Errno, SyscallResult};

pub struct RtcInode {
    metadata: InodeMeta,
    fs: Weak<DevFileSystem>,
}

impl RtcInode {
    pub fn new(fs: Arc<DevFileSystem>, parent: Arc<dyn Inode>) -> Arc<Self> {
        Arc::new(Self {
            metadata: InodeMeta::new_simple(
                fs.ino_pool.fetch_add(1, Ordering::Relaxed),
                0,
                0,
                InodeMode::S_IFCHR | InodeMode::S_IRUSR | InodeMode::S_IWUSR,
                "rtc".to_string(),
                parent,
            ),
            fs: Arc::downgrade(&fs),
        })
    }
}

#[async_trait]
impl InodeInternal for RtcInode {
    async fn read_direct(&self, buf: &mut [u8], _: isize) -> SyscallResult<isize> {
        buf.fill(0);
        Ok(buf.len() as isize)
    }

    async fn write_direct(&self, _: &[u8], _: isize) -> SyscallResult<isize> {
        Ok(0)
    }
}

impl Inode for RtcInode {
    fn metadata(&self) -> &InodeMeta {
        &self.metadata
    }

    fn file_system(&self) -> Weak<dyn FileSystem> {
        self.fs.clone()
    }

    fn ioctl(&self, _: usize, value: usize, _: usize, _: usize, _: usize) -> SyscallResult<i32> {
        let value = user_transmute_w::<RtcTime>(value)?.ok_or(Errno::EINVAL)?;
        *value = RtcTime::default();
        Ok(0)
    }
}

#[repr(C)]
#[derive(Default, AsBytes, FromZeroes, FromBytes)]
pub struct RtcTime {
    tm_sec: i32,
    tm_min: i32,
    tm_hour: i32,
    tm_mday: i32,
    tm_mon: i32,
    tm_year: i32,
}
