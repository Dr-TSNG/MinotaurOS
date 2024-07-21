use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::{Arc, Weak};
use core::cmp::min;
use core::sync::atomic::Ordering;
use async_trait::async_trait;
use crate::fs::ffi::InodeMode;
use crate::fs::file_system::FileSystem;
use crate::fs::procfs::ProcFileSystem;
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::processor::current_process;
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
                InodeMode::IFREG,
                "mounts".to_string(),
                "/mounts".to_string(),
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
    async fn read_direct(&self, buf: &mut [u8], offset: isize) -> SyscallResult<isize> {
        let mounts = current_process().inner.lock().mnt_ns.print_mounts();
        if offset as usize >= mounts.len() {
            return Ok(0);
        }
        let copy = min(buf.len(), mounts.len() - offset as usize);
        let to_copy = &mounts.as_bytes()[offset as usize..offset as usize + copy];
        buf[..copy].copy_from_slice(to_copy);
        Ok(copy as isize)
    }

    async fn write_direct(&self, _: &[u8], _: isize) -> SyscallResult<isize> {
        Ok(0)
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
