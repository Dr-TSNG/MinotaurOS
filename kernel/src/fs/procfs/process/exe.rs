use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use core::sync::atomic::Ordering;
use async_trait::async_trait;
use macros::InodeFactory;
use crate::fs::ffi::InodeMode;
use crate::fs::inode::{InodeInternal, InodeMeta};
use crate::fs::procfs::process::ProcessDirInode;
use crate::fs::procfs::ProcFileSystem;
use crate::process::Process;
use crate::result::{Errno, SyscallResult};

#[derive(InodeFactory)]
pub struct ExeInode {
    metadata: InodeMeta,
    fs: Weak<ProcFileSystem>,
    process: Weak<Process>,
}

impl ExeInode {
    pub fn new(fs: Arc<ProcFileSystem>, parent: Arc<ProcessDirInode>) -> Arc<Self> {
        Arc::new(Self {
            metadata: InodeMeta::new_simple(
                fs.ino_pool.fetch_add(1, Ordering::Relaxed),
                0,
                0,
                InodeMode::def_lnk(),
                "exe".to_string(),
                parent.clone(),
            ),
            fs: Arc::downgrade(&fs),
            process: parent.process.clone(),
        })
    }
}

#[async_trait]
impl InodeInternal for ExeInode {
    async fn do_readlink(self: Arc<Self>) -> SyscallResult<String> {
        let process = self.process.upgrade().ok_or(Errno::EBADF)?;
        let exe = process.inner.lock().exe.clone();
        Ok(exe)
    }
}
