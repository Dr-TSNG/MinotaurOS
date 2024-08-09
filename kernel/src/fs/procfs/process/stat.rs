use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::{Arc, Weak};
use core::cmp::min;
use core::sync::atomic::Ordering;
use async_trait::async_trait;
use macros::InodeFactory;
use crate::fs::ffi::InodeMode;
use crate::fs::procfs::ProcFileSystem;
use crate::fs::inode::{InodeInternal, InodeMeta};
use crate::fs::procfs::process::ProcessDirInode;
use crate::process::Process;
use crate::result::{Errno, SyscallResult};

#[derive(InodeFactory)]
pub struct StatInode {
    metadata: InodeMeta,
    fs: Weak<ProcFileSystem>,
    process: Weak<Process>,
}

impl StatInode {
    pub fn new(fs: Arc<ProcFileSystem>, parent: Arc<ProcessDirInode>) -> Arc<Self> {
        Arc::new(Self {
            metadata: InodeMeta::new_simple(
                fs.ino_pool.fetch_add(1, Ordering::Relaxed),
                0,
                0,
                InodeMode::S_IFREG | InodeMode::from_bits_retain(0o444),
                "stat".to_string(),
                parent.clone(),
            ),
            fs: Arc::downgrade(&fs),
            process: parent.process.clone(),
        })
    }
}

#[async_trait]
impl InodeInternal for StatInode {
    async fn read_direct(&self, buf: &mut [u8], offset: isize) -> SyscallResult<isize> {
        let process = self.process.upgrade().ok_or(Errno::EBADF)?;
        let stat = process.print_stat();
        if offset as usize >= stat.len() {
            return Ok(0);
        }
        let copy = min(buf.len(), stat.len() - offset as usize);
        let to_copy = &stat.as_bytes()[offset as usize..offset as usize + copy];
        buf[..copy].copy_from_slice(to_copy);
        Ok(copy as isize)
    }
}
