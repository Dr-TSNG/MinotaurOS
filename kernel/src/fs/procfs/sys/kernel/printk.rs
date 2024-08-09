use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::{Arc, Weak};
use core::cmp::min;
use core::sync::atomic::Ordering;
use async_trait::async_trait;
use macros::InodeFactory;
use crate::fs::ffi::InodeMode;
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::fs::procfs::ProcFileSystem;
use crate::result::SyscallResult;

#[derive(InodeFactory)]
pub struct PrintKInode {
    metadata: InodeMeta,
    fs: Weak<ProcFileSystem>,
}

impl PrintKInode {
    pub fn new(fs: Arc<ProcFileSystem>, parent: Arc<dyn Inode>) -> Arc<Self> {
        Arc::new(Self {
            metadata: InodeMeta::new_simple(
                fs.ino_pool.fetch_add(1, Ordering::Relaxed),
                0,
                0,
                InodeMode::S_IFREG | InodeMode::from_bits_retain(0o644),
                "printk".to_string(),
                parent,
            ),
            fs: Arc::downgrade(&fs),
        })
    }
}

#[async_trait]
impl InodeInternal for PrintKInode {
    async fn read_direct(&self, buf: &mut [u8], offset: isize) -> SyscallResult<isize> {
        if offset != 0 {
            return Ok(0);
        }
        let data = b"4 4 1 7\n";
        let read = min(buf.len(), data.len());
        buf[..read].copy_from_slice(&data[..read]);
        Ok(read as isize)
    }
}
