use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use async_trait::async_trait;
use crate::fs::devfs::DevFileSystem;
use crate::fs::ffi::InodeMode;
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::result::SyscallResult;
use crate::sched::ffi::TimeSpec;

pub struct NullInode(InodeMeta);

impl NullInode {
    pub fn new(fs: &DevFileSystem, parent: Arc<dyn Inode>) -> Arc<Self> {
        Arc::new(Self(InodeMeta::new(
            fs.ino_pool.fetch_add(1, Ordering::Relaxed),
            0,
            InodeMode::IFCHR,
            "null".to_string(),
            "/null".to_string(),
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
impl InodeInternal for NullInode {
    async fn read_direct(&self, _: &mut [u8], _: isize) -> SyscallResult<isize> {
        Ok(0)
    }

    async fn write_direct(&self, buf: &[u8], _: isize) -> SyscallResult<isize> {
        Ok(buf.len() as isize)
    }
}

impl Inode for NullInode {
    fn metadata(&self) -> &InodeMeta {
        &self.0
    }
}
