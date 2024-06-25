use crate::fs::devfs::net::NetInode;
use crate::fs::ffi::InodeMode;
use alloc::string::ToString;
use alloc::sync::Arc;
use async_trait::async_trait;
use core::sync::atomic::Ordering;

use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::result::SyscallResult;
use crate::sched::ffi::TimeSpec;

pub struct UnixSockNode {
    metadata: InodeMeta,
}

// 需要指定InodeMode::IFSOCK
impl UnixSockNode {
    pub fn new() -> SyscallResult<Arc<Self>> {
        let now = TimeSpec::default();
        todo!()
    }
}

impl InodeInternal for UnixSockNode {}

#[async_trait]
impl Inode for UnixSockNode {
    fn metadata(&self) -> &InodeMeta {
        &self.metadata
    }
}
