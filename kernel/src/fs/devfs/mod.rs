use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicUsize, Ordering};
use async_trait::async_trait;
use tap::Tap;
use crate::fs::devfs::net::NetInode;
use crate::fs::devfs::null::NullInode;
use crate::fs::devfs::zero::ZeroInode;
use crate::fs::devfs::rtc::RtcInode;
use crate::fs::ffi::{InodeMode, VfsFlags};
use crate::fs::file_system::{FileSystem, FileSystemMeta, FileSystemType};
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::result::{Errno, SyscallResult};
use crate::sched::ffi::TimeSpec;
use crate::sync::mutex::Mutex;
use crate::sync::once::LateInit;

mod net;
mod null;
pub mod tty;
mod zero;
mod rtc;

pub struct DevFileSystem {
    vfsmeta: FileSystemMeta,
    ino_pool: AtomicUsize,
    root: LateInit<Arc<RootInode>>,
}

impl DevFileSystem {
    pub fn new(flags: VfsFlags, parent: Option<Arc<dyn Inode>>) -> Arc<Self> {
        let fs = Arc::new(Self {
            vfsmeta: FileSystemMeta::new(FileSystemType::DEVFS, flags),
            ino_pool: AtomicUsize::new(1),
            root: LateInit::new(),
        });
        fs.root.init(RootInode::new(&fs, parent));
        fs
    }
}

impl FileSystem for DevFileSystem {
    fn metadata(&self) -> &FileSystemMeta {
        &self.vfsmeta
    }

    fn root(&self) -> Arc<dyn Inode> {
        self.root.clone()
    }
}

struct RootInode {
    metadata: InodeMeta,
    fs: Weak<DevFileSystem>,
    children: Mutex<BTreeMap<String, Arc<dyn Inode>>>,
}

impl RootInode {
    pub fn new(fs: &Arc<DevFileSystem>, parent: Option<Arc<dyn Inode>>) -> Arc<Self> {
        let root = Arc::new(Self {
            metadata: InodeMeta::new(
                fs.ino_pool.fetch_add(1, Ordering::Relaxed),
                0,
                InodeMode::IFDIR,
                "/".to_string(),
                "/".to_string(),
                parent,
                None,
                TimeSpec::default(),
                TimeSpec::default(),
                TimeSpec::default(),
                0,
            ),
            fs: Arc::downgrade(fs),
            children: Mutex::new(BTreeMap::new()),
        });
        root.children.lock().tap_mut(|it| {
            it.insert("null".to_string(), NullInode::new(fs.clone(), root.clone()));
            it.insert("zero".to_string(), ZeroInode::new(fs.clone(), root.clone()));
            it.insert("net".to_string(), NetInode::new(fs.clone(), root.clone()));
            it.insert("rtc".to_string(), RtcInode::new(fs.clone(), root.clone()));
        });
        root
    }
}

#[async_trait]
impl InodeInternal for RootInode {
    async fn do_lookup_name(self: Arc<Self>, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        self.children.lock().get(name).cloned().ok_or(Errno::ENOENT)
    }

    async fn do_lookup_idx(self: Arc<Self>, idx: usize) -> SyscallResult<Arc<dyn Inode>> {
        self.children.lock().values().nth(idx).cloned().ok_or(Errno::ENOENT)
    }
}

impl Inode for RootInode {
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
