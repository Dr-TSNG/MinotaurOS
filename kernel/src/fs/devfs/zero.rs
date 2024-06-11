use crate::fs::devfs::DevFileSystem;
use crate::fs::ffi::InodeMode;
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::result::SyscallResult;
use crate::sched::ffi::TimeSpec;
use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use async_trait::async_trait;
use core::sync::atomic::Ordering;

pub struct ZeroInode(InodeMeta);

impl ZeroInode {
    pub fn new(fs: &DevFileSystem, parent: Arc<dyn Inode>) -> Arc<Self> {
        Arc::new(Self(InodeMeta::new(
            fs.ino_pool.fetch_add(1, Ordering::Relaxed),
            0,
            InodeMode::IFCHR,
            "zero".to_string(),
            "/zero".to_string(),
            Some(parent),
            None,
            TimeSpec::default(),
            TimeSpec::default(),
            TimeSpec::default(),
            0,
        )))
    }
}

#[async_trait]
impl InodeInternal for ZeroInode {
    async fn read_direct(&self, buf: &mut [u8], _: isize) -> SyscallResult<isize> {
        buf.fill(0);
        Ok(buf.len() as isize)
    }

    async fn write_direct(&self, _: &[u8], _: isize) -> SyscallResult<isize> {
        Ok(0)
    }
}

impl Inode for ZeroInode {
    fn metadata(&self) -> &InodeMeta {
        &self.0
    }
}
