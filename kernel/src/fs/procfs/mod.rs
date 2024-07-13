use alloc::string::ToString;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicUsize, Ordering};
use tap::Tap;
use crate::fs::ffi::{InodeMode, VfsFlags};
use crate::fs::file_system::{FileSystem, FileSystemMeta, FileSystemType};
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::sched::ffi::TimeSpec;
use crate::sync::once::LateInit;

pub struct ProcFileSystem {
    vfsmeta: FileSystemMeta,
    ino_pool: AtomicUsize,
    root: LateInit<Arc<RootInode>>,
}

impl ProcFileSystem {
    pub fn new(flags: VfsFlags, parent: Option<Arc<dyn Inode>>) -> Arc<Self> {
        let fs = Arc::new(Self {
            vfsmeta: FileSystemMeta::new(FileSystemType::PROCFS, flags),
            ino_pool: AtomicUsize::new(1),
            root: LateInit::new(),
        });
        fs.root.init(RootInode::new(&fs, parent));
        fs
    }
}

impl FileSystem for ProcFileSystem {
    fn metadata(&self) -> &FileSystemMeta {
        &self.vfsmeta
    }

    fn root(&self) -> Arc<dyn Inode> {
        self.root.clone()
    }
}

struct RootInode {
    metadata: InodeMeta,
    fs: Weak<ProcFileSystem>,
}

impl RootInode {
    pub fn new(fs: &Arc<ProcFileSystem>, parent: Option<Arc<dyn Inode>>) -> Arc<Self> {
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
        });
        root
    }
}

impl InodeInternal for RootInode {}

impl Inode for RootInode {
    fn metadata(&self) -> &InodeMeta {
        &self.metadata
    }

    fn file_system(&self) -> Weak<dyn FileSystem> {
        self.fs.clone()
    }
}
