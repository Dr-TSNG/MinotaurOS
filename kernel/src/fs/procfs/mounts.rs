use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::Ordering;
use async_trait::async_trait;
use crate::fs::ffi::InodeMode;
use crate::fs::file_system::FileSystem;
use crate::fs::procfs::ProcFileSystem;
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::result::{Errno, SyscallResult};
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
        let dev_name = "proc";
        let mount_point = "/proc";
        let fstype = "proc";
        let flags = "rw";
        let buf_str = dev_name.to_owned()
            + " "
            + mount_point
            + " "
            + fstype
            + " "
            + flags
            + " 0 0\n";
        let len = buf_str.len();
        if offset == len as isize {
            Ok(0)
        }
        else {
            buf[..len].copy_from_slice(buf_str.as_bytes());
            Ok(len as isize)
        }
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

    fn ioctl(&self, request: usize, value: usize, arg3: usize, arg4: usize, arg5: usize) -> SyscallResult<i32> {
        Err(Errno::ENOTTY)
    }
}
