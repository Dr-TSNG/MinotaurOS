use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use core::sync::atomic::Ordering;
use async_trait::async_trait;
use macros::InodeFactory;
use crate::fs::ffi::InodeMode;
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::fs::procfs::ProcFileSystem;
use crate::processor::current_process;
use crate::result::SyscallResult;

#[derive(InodeFactory)]
pub struct SelfInode {
    metadata: InodeMeta,
    fs: Weak<ProcFileSystem>,
}

impl SelfInode {
    pub fn new(fs: Arc<ProcFileSystem>, parent: Arc<dyn Inode>) -> Arc<Self> {
        Arc::new(Self {
            metadata: InodeMeta::new_simple(
                fs.ino_pool.fetch_add(1, Ordering::Relaxed),
                0,
                0,
                InodeMode::def_lnk(),
                "self".to_string(),
                parent,
            ),
            fs: Arc::downgrade(&fs),
        })
    }
}

#[async_trait]
impl InodeInternal for SelfInode {
    async fn do_readlink(self: Arc<Self>) -> SyscallResult<String> {
        Ok(current_process().pid.0.to_string())
    }
}
