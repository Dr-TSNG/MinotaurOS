use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::sync::Weak;
use core::sync::atomic::Ordering;
use crate::fs::devfs::DevFileSystem;
use crate::fs::ffi::InodeMode;
use crate::fs::file_system::FileSystem;
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::sched::ffi::TimeSpec;

pub struct NetInode {
    metadata: InodeMeta,
    socket_id: usize, // socket handler, no use now
    fs: Weak<DevFileSystem>,
}

// 需要指定InodeMode::IFSOCK
impl NetInode {
    pub fn new(fs: Arc<DevFileSystem>, parent: Arc<dyn Inode>) -> Arc<Self> {
        Arc::new(Self {
            metadata: InodeMeta::new(
                fs.ino_pool.fetch_add(1, Ordering::Relaxed),
                0,
                InodeMode::IFDIR,
                "net".to_string(),
                "/net".to_string(),
                Some(parent),
                None,
                TimeSpec::default(),
                TimeSpec::default(),
                TimeSpec::default(),
                0,
            ),
            socket_id: 0,
            fs: Arc::downgrade(&fs),
        })
    }
}

impl InodeInternal for NetInode {}

impl Inode for NetInode {
    fn metadata(&self) -> &InodeMeta {
        &self.metadata
    }

    fn file_system(&self) -> Weak<dyn FileSystem> {
        self.fs.clone()
    }
}
