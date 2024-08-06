use alloc::boxed::Box;
use alloc::format;
use alloc::string::ToString;
use alloc::sync::{Arc, Weak};
use core::cmp::min;
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

pub struct MapsInode {
    metadata: InodeMeta,
    fs: Weak<ProcFileSystem>,
    process: Weak<Process>,
}

impl MapsInode {
    pub fn new(
        fs: Arc<ProcFileSystem>,
        parent: Arc<ProcessDirInode>,
    ) -> Arc<Self> {
        Arc::new(Self {
            metadata: InodeMeta::new(
                fs.ino_pool.fetch_add(1, Ordering::Relaxed),
                0,
                0,
                0,
                InodeMode::S_IFREG | InodeMode::from_bits_truncate(0o444),
                "maps".to_string(),
                format!("{}/maps", parent.metadata.name),
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
impl InodeInternal for MapsInode {
    async fn read_direct(&self, buf: &mut [u8], offset: isize) -> SyscallResult<isize> {
        let process = self.process.upgrade().ok_or(Errno::EBADF)?;
        let maps = process.inner.lock().addr_space.lock().display_maps();
        let mut skipped = 0;
        let mut pos = 0;
        let iter = maps.into_iter().skip_while(|line| {
            if offset > skipped {
                skipped += line.len() as isize;
                true
            } else {
                false
            }
        });
        for line in iter {
            let read = min(buf.len() - pos, line.len());
            buf[pos..pos + read].copy_from_slice(&line.as_bytes()[..read]);
            pos += read;
            if pos == buf.len() {
                break;
            }
        }
        Ok(pos as isize)
    }
}

impl Inode for MapsInode {
    fn metadata(&self) -> &InodeMeta {
        &self.metadata
    }

    fn file_system(&self) -> Weak<dyn FileSystem> {
        self.fs.clone()
    }
}
