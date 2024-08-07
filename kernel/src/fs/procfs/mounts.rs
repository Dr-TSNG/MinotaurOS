use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use core::sync::atomic::Ordering;
use async_trait::async_trait;
use crate::fs::ffi::InodeMode;
use crate::fs::file_system::FileSystem;
use crate::fs::procfs::ProcFileSystem;
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::result::SyscallResult;
use crate::sched::ffi::TimeSpec;

pub struct MountsInode {
    metadata: InodeMeta,
    fs: Weak<ProcFileSystem>,

}

impl MountsInode {
    pub fn new(fs: Arc<ProcFileSystem>, parent: Arc<dyn Inode>) -> Arc<Self> {
        Arc::new(Self {
            metadata: InodeMeta::new(
                fs.ino_pool.fetch_add(1, Ordering::Relaxed),
                0,
                0,
                0,
                InodeMode::def_lnk(),
                "mounts".to_string(),
                "mounts".to_string(),
                Some(parent),
                None,
                TimeSpec::default(),
                TimeSpec::default(),
                TimeSpec::default(),
                0,
            ),
            fs: Arc::downgrade(&fs),
        })
    }
}

#[async_trait]
impl InodeInternal for MountsInode {
    async fn do_readlink(self: Arc<Self>) -> SyscallResult<String> {
        Ok("self/mounts".to_string())
    }
}

impl Inode for MountsInode {
    fn metadata(&self) -> &InodeMeta {
        &self.metadata
    }

    fn file_system(&self) -> Weak<dyn FileSystem> {
        self.fs.clone()
    }
}
