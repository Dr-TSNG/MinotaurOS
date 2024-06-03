use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use async_trait::async_trait;
use bitvec_rs::BitVec;

use crate::fs::devfs::DevFileSystem;
use crate::fs::fat32::FAT32FileSystem;
use crate::fs::ffi::InodeMode;
use crate::fs::inode::{Inode, InodeChild, InodeInternal, InodeMeta, InodeMetaInner};
use crate::result::SyscallResult;
use crate::sync::block_on;
use crate::sync::mutex::AsyncMutex;

pub struct NetInode {
    metadata: InodeMeta,
    fs: Weak<FAT32FileSystem>,
    ext: Arc<AsyncMutex<FAT32InodeExt>>,
}
struct FAT32InodeExt {
    dir_occupy: BitVec,
    clusters: Vec<usize>,
}

impl NetInode {
    pub fn new(fs: &DevFileSystem, parent: Arc<dyn Inode>) -> SyscallResult<Arc<Self>> {
        todo!()
    }
}
#[async_trait]
impl InodeInternal for NetInode {
    async fn read_direct(&self, buf: &mut [u8], offset: isize) -> SyscallResult<isize> {
        todo!()
    }
    async fn write_direct(&self, buf: &[u8], offset: isize) -> SyscallResult<isize> {
        todo!()
    }
    async fn truncate_direct(&self, size: isize) -> SyscallResult {
        todo!()
    }
    async fn do_create(
        self: Arc<Self>,
        inner: &mut InodeMetaInner,
        mode: InodeMode,
        name: &str,
    ) -> SyscallResult<InodeChild> {
        todo!()
    }
}

#[async_trait]
impl Inode for NetInode {
    fn metadata(&self) -> &InodeMeta {
        &self.metadata
    }
}

impl Drop for NetInode {
    fn drop(&mut self) {
        if let Some(page_cache) = self.metadata.page_cache.as_ref() {
            block_on(page_cache.sync_all(self)).unwrap();
        }
    }
}
