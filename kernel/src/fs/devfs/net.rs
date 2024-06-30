use alloc::boxed::Box;
use alloc::sync::Weak;
use alloc::string::ToString;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use spin::Mutex;

use crate::fs::devfs::DevFileSystem;
use crate::fs::ffi::InodeMode;
use crate::fs::file::{File, FileMeta, FileMetaInner};
use crate::fs::file_system::FileSystem;
use crate::fs::inode::{Inode, InodeInternal, InodeMeta, InodeMetaInner};
use crate::result::SyscallResult;
use crate::sched::ffi::TimeSpec;

pub struct NetInode {
    metadata: InodeMeta,
    socket_id: usize, // socket handler, no use now
    fs: Weak<DevFileSystem>,
}
static INO_POOL: AtomicUsize = AtomicUsize::new(0);

// 需要指定InodeMode::IFSOCK
impl NetInode {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            metadata: InodeMeta::new(
                0,
                0,
                InodeMode::IFSOCK,
                "".to_string(),
                "".to_string(),
                None,
                None,
                TimeSpec::default(),
                TimeSpec::default(),
                TimeSpec::default(),
                0,
            ),
            socket_id: 0,
            fs: Default::default(),
        })
    }
}

///
/// TCP UDP socket中没有使用这写方法。。。只使用了默认的Inode Trait的方法
///
#[async_trait]
impl InodeInternal for NetInode {

}

#[async_trait]
impl Inode for NetInode {
    fn metadata(&self) -> &InodeMeta {
        &self.metadata
    }

    fn file_system(&self) -> alloc::sync::Weak<dyn FileSystem> {
        self.fs.clone()
    }
}

///
/// 不需要直接操作net file的inode
///
impl Drop for NetInode {
    fn drop(&mut self) {}
}
