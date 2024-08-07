use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use core::sync::atomic::Ordering;
use async_trait::async_trait;
use macros::InodeFactory;
use crate::fs::ffi::InodeMode;
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::fs::procfs::process::exe::ExeInode;
use crate::fs::procfs::process::maps::MapsInode;
use crate::fs::procfs::process::mounts::MountsInode;
use crate::fs::procfs::ProcFileSystem;
use crate::process::Process;
use crate::result::{Errno, SyscallResult};
use crate::sync::mutex::Mutex;

mod exe;
mod maps;
mod mounts;

#[derive(InodeFactory)]
pub struct ProcessDirInode {
    metadata: InodeMeta,
    fs: Weak<ProcFileSystem>,
    process: Weak<Process>,
    inner: Mutex<ProcessDirInner>,
}

#[derive(Default)]
struct ProcessDirInner {
    initialized: bool,
    children: BTreeMap<String, Arc<dyn Inode>>,
}

impl ProcessDirInode {
    pub fn new(
        fs: Arc<ProcFileSystem>,
        parent: Arc<dyn Inode>,
        process: Arc<Process>,
    ) -> Arc<Self> {
        Arc::new(Self {
            metadata: InodeMeta::new_simple(
                fs.ino_pool.fetch_add(1, Ordering::Relaxed),
                0,
                0,
                InodeMode::S_IFDIR | InodeMode::from_bits_retain(0o555),
                process.pid.0.to_string(),
                parent,
            ),
            fs: Arc::downgrade(&fs),
            process: Arc::downgrade(&process),
            inner: Default::default(),
        })
    }
}

impl ProcessDirInner {
    fn init_children(&mut self, this: Arc<ProcessDirInode>) -> SyscallResult {
        let fs = this.fs.upgrade().ok_or(Errno::EIO)?;
        self.children.insert("exe".to_string(), ExeInode::new(fs.clone(), this.clone()));
        self.children.insert("maps".to_string(), MapsInode::new(fs.clone(), this.clone()));
        self.children.insert("mounts".to_string(), MountsInode::new(fs.clone(), this.clone()));
        self.initialized = true;
        Ok(())
    }
}

#[async_trait]
impl InodeInternal for ProcessDirInode {
    async fn do_lookup_name(self: Arc<Self>, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        let mut inner = self.inner.lock();
        if !inner.initialized {
            inner.init_children(self.clone())?;
        }
        match inner.children.get(name) {
            Some(inode) => Ok(inode.clone()),
            None => Err(Errno::ENOENT),
        }
    }

    async fn do_lookup_idx(self: Arc<Self>, idx: usize) -> SyscallResult<Arc<dyn Inode>> {
        let mut inner = self.inner.lock();
        if !inner.initialized {
            inner.init_children(self.clone())?;
        }
        match inner.children.values().nth(idx) {
            Some(inode) => Ok(inode.clone()),
            None => Err(Errno::ENOENT),
        }
    }
}
