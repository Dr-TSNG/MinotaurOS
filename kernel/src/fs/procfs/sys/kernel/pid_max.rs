use alloc::boxed::Box;
use alloc::format;
use alloc::string::ToString;
use alloc::sync::{Arc, Weak};
use core::cmp::min;
use core::sync::atomic::Ordering;
use async_trait::async_trait;
use macros::InodeFactory;
use crate::fs::ffi::InodeMode;
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::fs::procfs::ProcFileSystem;
use crate::result::{Errno, SyscallResult};
use crate::system::PID_MAX;

#[derive(InodeFactory)]
pub struct PidMaxInode {
    metadata: InodeMeta,
    fs: Weak<ProcFileSystem>,
}

impl PidMaxInode {
    pub fn new(fs: Arc<ProcFileSystem>, parent: Arc<dyn Inode>) -> Arc<Self> {
        Arc::new(Self {
            metadata: InodeMeta::new_simple(
                fs.ino_pool.fetch_add(1, Ordering::Relaxed),
                0,
                0,
                InodeMode::S_IFREG | InodeMode::from_bits_retain(0o644),
                "pid_max".to_string(),
                parent,
            ),
            fs: Arc::downgrade(&fs),
        })
    }
}

#[async_trait]
impl InodeInternal for PidMaxInode {
    async fn read_direct(&self, buf: &mut [u8], offset: isize) -> SyscallResult<isize> {
        if offset != 0 {
            return Ok(0);
        }
        let data = format!("{}\n", *PID_MAX.lock()).into_bytes();
        let read = min(buf.len(), data.len());
        buf[..read].copy_from_slice(&data[..read]);
        Ok(read as isize)
    }

    async fn write_direct(&self, buf: &[u8], offset: isize) -> SyscallResult<isize> {
        if offset != 0 {
            return Ok(0);
        }
        let mut pid_max = PID_MAX.lock();
        let new_pid_max = core::str::from_utf8(buf).ok()
            .and_then(|s| s.ends_with('\n').then_some(s))
            .and_then(|s| s.trim_end().parse::<usize>().ok())
            .ok_or(Errno::EINVAL)?;
        *pid_max = new_pid_max;
        Ok(buf.len() as isize)
    }

    async fn truncate_direct(&self, _: isize) -> SyscallResult {
        Ok(())
    }
}
