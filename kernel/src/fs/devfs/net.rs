use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;

use crate::fs::devfs::DevFileSystem;
use crate::fs::ffi::InodeMode;
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::result::SyscallResult;
use crate::sched::ffi::TimeSpec;

pub struct NetInode {
    metadata: InodeMeta,
    socket_id: usize,   // socket handler
}
static INO_POOL: AtomicUsize = AtomicUsize::new(0);

impl NetInode {
    pub fn new() -> SyscallResult<Arc<Self>> {
        let now = TimeSpec::default();
        let metadata = InodeMeta::new(
            INO_POOL.fetch_add(1,Ordering::Acquire),
            0,
            InodeMode::IFSOCK,
            "socket_file".to_string(),
            "/socket_file".to_string(),
            None,
            None,
            now.clone(),
            now.clone(),
            now,
            0,
        );
        Ok(Arc::new(Self{metadata,socket_id}))
    }
}

///
/// TCP UDP socket中没有使用这写方法。。。只使用了默认的Inode Trait的方法
///
#[async_trait]
impl InodeInternal for NetInode {
    async fn read_direct(&self, mut buf: &mut [u8], offset: isize) -> SyscallResult<isize> {
        todo!()
    }
    async fn write_direct(&self, buf: &[u8], offset: isize) -> SyscallResult<isize> {
        todo!()
    }
    async fn truncate_direct(&self, size: isize) -> SyscallResult {
        todo!()
    }
}

#[async_trait]
impl Inode for NetInode {
    fn metadata(&self) -> &InodeMeta {
        &self.metadata
    }
}

///
/// 未完成，可能需要进行Drop之前关闭套接字等
///
impl Drop for NetInode {
    fn drop(&mut self) {
        todo!()
    }
}

