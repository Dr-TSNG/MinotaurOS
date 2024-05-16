use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::fs::devfs::null::NullInode;
use crate::fs::devfs::zero::ZeroInode;
use crate::fs::ffi::{InodeMode, VfsFlags};
use crate::fs::file_system::{FileSystem, FileSystemMeta, FileSystemType};
use crate::fs::inode::{Inode, InodeChild, InodeInternal, InodeMeta};
use crate::sched::ffi::TimeSpec;
use crate::sync::once::LateInit;

mod null;
pub mod tty;
mod zero;

pub struct DevFileSystem {
    vfsmeta: FileSystemMeta,
    ino_pool: AtomicUsize,
    root: LateInit<Arc<RootInode>>,
}

impl DevFileSystem {
    pub fn new(flags: VfsFlags, source: String, parent: Option<Arc<dyn Inode>>) -> Arc<Self> {
        let fs = Arc::new(Self {
            vfsmeta: FileSystemMeta::new(FileSystemType::DEVFS, flags),
            ino_pool: AtomicUsize::new(1),
            root: LateInit::new(),
        });
        fs.root.init(RootInode::new(&fs, source, parent));
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
}

impl RootInode {
    pub fn new(fs: &Arc<DevFileSystem>, source: String, parent: Option<Arc<dyn Inode>>) -> Arc<Self> {
        let root = Arc::new(Self {
            metadata: InodeMeta::new(
                fs.ino_pool.fetch_add(1, Ordering::Relaxed),
                0,
                InodeMode::IFDIR,
                source,
                "/".to_string(),
                parent,
                None,
                TimeSpec::default(),
                TimeSpec::default(),
                TimeSpec::default(),
                0,
            ),
            fs: Arc::downgrade(fs),
        });
        root.metadata.inner.lock().apply_mut(|inner| {
            inner.children.insert("null".to_string(), InodeChild::new(NullInode::new(fs, root.clone()), Box::new(())));
            inner.children.insert("zero".to_string(), InodeChild::new(ZeroInode::new(fs, root.clone()), Box::new(())));
            inner.children_loaded = true;
        });
        root
    }
}

impl InodeInternal for RootInode {}

impl Inode for RootInode {
    fn metadata(&self) -> &InodeMeta {
        &self.metadata
    }
}
