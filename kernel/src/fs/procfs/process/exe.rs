use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use core::sync::atomic::Ordering;
use async_trait::async_trait;
use crate::fs::ffi::InodeMode;
use crate::fs::file_system::FileSystem;
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::fs::procfs::process::ProcessDirInode;
use crate::fs::procfs::ProcFileSystem;
use crate::process::Process;
use crate::result::{Errno, SyscallResult};
use crate::sched::ffi::TimeSpec;

pub struct ExeInode {
    metadata: InodeMeta,
    fs: Weak<ProcFileSystem>,
    process: Weak<Process>,
}

impl ExeInode {
    pub fn new(fs: Arc<ProcFileSystem>, parent: Arc<ProcessDirInode>) -> Arc<Self> {
        Arc::new(Self {
            metadata: InodeMeta::new(
                fs.ino_pool.fetch_add(1, Ordering::Relaxed),
                0,
                0,
                0,
                InodeMode::S_IFLNK | InodeMode::from_bits_truncate(0o777),
                "exe".to_string(),
                format!("{}/exe", parent.metadata.path),
                Some(parent.clone()),
                None,
                TimeSpec::default(),
                TimeSpec::default(),
                TimeSpec::default(),
                0,
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

impl Inode for ExeInode {
    fn metadata(&self) -> &InodeMeta {
        &self.metadata
    }

    fn file_system(&self) -> Weak<dyn FileSystem> {
        self.fs.clone()
    }
}
