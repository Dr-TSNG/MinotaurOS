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
pub struct MountsInode {
    metadata: InodeMeta,
    fs: Weak<ProcFileSystem>,
    process: Weak<Process>,
}

impl MountsInode {
    pub fn new(fs: Arc<ProcFileSystem>, parent: Arc<ProcessDirInode>) -> Arc<Self> {
        Arc::new(Self {
            metadata: InodeMeta::new_simple(
                fs.ino_pool.fetch_add(1, Ordering::Relaxed),
                0,
                0,
                InodeMode::S_IFREG | InodeMode::from_bits_retain(0o444),
                "mounts".to_string(),
                parent.clone(),
            ),
            fs: Arc::downgrade(&fs),
            process: parent.process.clone(),
        })
    }
}

#[async_trait]
impl InodeInternal for MountsInode {
    async fn read_direct(&self, buf: &mut [u8], offset: isize) -> SyscallResult<isize> {
        let process = self.process.upgrade().ok_or(Errno::EBADF)?;
        let mounts = process.inner.lock().mnt_ns.print_mounts();
        if offset as usize >= mounts.len() {
            return Ok(0);
        }
        let copy = min(buf.len(), mounts.len() - offset as usize);
        let to_copy = &mounts.as_bytes()[offset as usize..offset as usize + copy];
        buf[..copy].copy_from_slice(to_copy);
        Ok(copy as isize)
    }
}
