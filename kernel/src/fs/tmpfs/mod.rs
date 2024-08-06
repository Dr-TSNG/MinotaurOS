use alloc::sync::Arc;
use core::sync::atomic::AtomicUsize;
use crate::fs::ffi::VfsFlags;
use crate::fs::file_system::{FileSystem, FileSystemMeta, FileSystemType};
use crate::fs::inode::Inode;
use crate::fs::tmpfs::inode::TmpfsInode;
use crate::result::SyscallResult;
use crate::sync::mutex::Mutex;
use crate::sync::once::LateInit;

mod inode;

pub struct TmpFileSystem {
    vfsmeta: FileSystemMeta,
    flags: Mutex<VfsFlags>,
    ino_pool: AtomicUsize,
    root: LateInit<Arc<TmpfsInode>>,
}

impl TmpFileSystem {
    pub fn new(source: Option<&str>, mut flags: VfsFlags, parent: Option<Arc<dyn Inode>>) -> Arc<Self> {
        let source = source.unwrap_or("tmpfs");
        if !flags.contains(VfsFlags::ST_RDONLY) {
            flags |= VfsFlags::ST_WRITE;
        }
        let fs = Arc::new(Self {
            vfsmeta: FileSystemMeta::new(0, source, FileSystemType::TMPFS),
            flags: Mutex::new(flags),
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

    fn flags(&self) -> VfsFlags {
        self.flags.lock().clone()
    }

    fn root(&self) -> Arc<dyn Inode> {
        self.root.clone()
    }

    fn remount(&self, flags: VfsFlags) -> SyscallResult {
        *self.flags.lock() = flags;
        Ok(())
    }
}
