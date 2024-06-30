use crate::fs::devfs::net::NetInode;
use crate::fs::ffi::InodeMode;
use alloc::string::ToString;
use alloc::sync::{Arc, Weak};
use async_trait::async_trait;
use core::sync::atomic::Ordering;
use crate::fs::devfs::DevFileSystem;
use crate::fs::file_system::FileSystem;

use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::result::SyscallResult;
use crate::sched::ffi::TimeSpec;

pub struct UnixSockNode {
    metadata: InodeMeta,
    fs: Weak<DevFileSystem>,
}

// 需要指定InodeMode::IFSOCK
impl UnixSockNode {
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
            fs: Default::default(),
        })
    }
}

impl InodeInternal for UnixSockNode {}

#[async_trait]
impl Inode for UnixSockNode {
    fn metadata(&self) -> &InodeMeta {
        &self.metadata
    }

    fn file_system(&self) -> Weak<dyn FileSystem> {
        self.fs.clone()
    }
}
