use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::Ordering;
use async_trait::async_trait;
use macros::InodeFactory;
use crate::fs::devfs::DevFileSystem;
use crate::fs::ffi::InodeMode;
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::result::SyscallResult;

#[derive(InodeFactory)]
pub struct NullInode {
    metadata: InodeMeta,
    fs: Weak<DevFileSystem>,
}

impl NullInode {
    pub fn new(fs: Arc<DevFileSystem>, parent: Arc<dyn Inode>) -> Arc<Self> {
        Arc::new(Self {
            metadata: InodeMeta::new_simple(
                fs.ino_pool.fetch_add(1, Ordering::Relaxed),
                0,
                0,
                InodeMode::S_IFCHR | InodeMode::from_bits_retain(0o666),
                "null".to_string(),
                parent,
            ),
            fs: Arc::downgrade(&fs),
        })
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
