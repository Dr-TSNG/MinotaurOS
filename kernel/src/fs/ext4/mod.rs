use alloc::sync::Arc;
use core::mem::ManuallyDrop;
use crate::driver::BlockDevice;
use crate::fs::ext4::inode::Ext4Inode;
use crate::fs::ext4::wrapper::Ext4;
use crate::fs::ffi::VfsFlags;
use crate::fs::file_system::{FileSystem, FileSystemMeta, FileSystemType};
use crate::fs::inode::Inode;
use crate::sync::once::LateInit;

mod inode;
mod wrapper;

pub struct Ext4FileSystem {
    device: Arc<dyn BlockDevice>,
    vfsmeta: FileSystemMeta,
    ext4: Ext4,
    root: ManuallyDrop<LateInit<Arc<Ext4Inode>>>,
}

impl Ext4FileSystem {
    pub fn new(
        device: Arc<dyn BlockDevice>,
        flags: VfsFlags,
    ) -> Arc<Self> {
        let fs = Arc::new(Ext4FileSystem {
            device: device.clone(),
            vfsmeta: FileSystemMeta::new(FileSystemType::EXT4, flags),
            ext4: Ext4::new(device),
            root: ManuallyDrop::new(LateInit::new()),
        });
        fs.root.init(Ext4Inode::root(&fs, None));
        fs
    }
}

impl FileSystem for Ext4FileSystem {
    fn metadata(&self) -> &FileSystemMeta {
        &self.vfsmeta
    }

    fn root(&self) -> Arc<dyn Inode> {
        self.root.clone()
    }
}
