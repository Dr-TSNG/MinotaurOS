use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::Ordering;
use async_trait::async_trait;
use rand::RngCore;
use crate::driver::random::{RNG};
use crate::fs::devfs::DevFileSystem;
use crate::fs::ffi::{InodeMode};
use crate::fs::file::File;
use crate::fs::file_system::FileSystem;
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::result::{Errno, SyscallResult};
use crate::sched::ffi::TimeSpec;

pub struct UrandomInode(InodeMeta, Weak<DevFileSystem>);

impl UrandomInode {
    pub fn new(fs: Arc<DevFileSystem>, parent: Arc<dyn Inode>) -> Arc<Self> {
        Arc::new(Self(InodeMeta::new(
            fs.ino_pool.fetch_add(1, Ordering::Relaxed),
            0,
            InodeMode::IFCHR,
            "urandom".to_string(),
            "/urandom".to_string(),
            Some(parent),
            None,
            TimeSpec::default(),
            TimeSpec::default(),
            TimeSpec::default(),
            512,
        ), Arc::downgrade(&fs)))
    }
}


#[async_trait]
impl InodeInternal for UrandomInode {
    async fn read_direct(&self, buf: &mut [u8], _: isize) -> SyscallResult<isize> {
        unsafe {
            RNG.fill_bytes(buf);
        }
        Ok(buf.len() as isize)
    }

    async fn write_direct(&self, _: &[u8], _: isize) -> SyscallResult<isize> {
        Ok(0)
    }
}

impl Inode for UrandomInode {
    fn metadata(&self) -> &InodeMeta {
        &self.0
    }

    fn file_system(&self) -> Weak<dyn FileSystem> {
        self.1.clone()
    }

    fn ioctl(&self, request: usize, value: usize, arg3: usize, arg4: usize, arg5: usize) -> SyscallResult<i32> {
        Err(Errno::ENOTTY)
    }
}
