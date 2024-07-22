use alloc::sync::Arc;
use core::sync::atomic::AtomicUsize;
use crate::fs::ffi::VfsFlags;
use crate::fs::file_system::{FileSystem, FileSystemMeta, FileSystemType};
use crate::fs::inode::Inode;
use crate::fs::tmpfs::inode::TmpfsInode;
use crate::sync::once::LateInit;

mod inode;

pub struct TmpFileSystem {
    vfsmeta: FileSystemMeta,
    ino_pool: AtomicUsize,
    root: LateInit<Arc<TmpfsInode>>,
}

impl TmpFileSystem {
    pub fn new(flags: VfsFlags, parent: Option<Arc<dyn Inode>>) -> Arc<Self> {
        let fs = Arc::new(Self {
            vfsmeta: FileSystemMeta::new(FileSystemType::TMPFS, flags),
            ino_pool: AtomicUsize::new(1),
            root: LateInit::new(),
        });
        fs.root.init(TmpfsInode::root(&fs, parent));
        fs
    }
}

impl FileSystem for TmpFileSystem {
    fn metadata(&self) -> &FileSystemMeta {
        &self.vfsmeta
    }

    fn root(&self) -> Arc<dyn Inode> {
        self.root.clone()
    }
}
