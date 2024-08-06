use alloc::sync::Arc;
use core::mem::ManuallyDrop;
use crate::driver::BlockDevice;
use crate::fs::ext4::inode::Ext4Inode;
use crate::fs::ext4::wrapper::Ext4;
use crate::fs::ffi::VfsFlags;
use crate::fs::file_system::{FileSystem, FileSystemMeta, FileSystemType};
use crate::fs::inode::Inode;
use crate::sync::mutex::AsyncMutex;
use crate::sync::once::LateInit;

mod inode;
mod wrapper;

pub struct Ext4FileSystem {
    device: Arc<dyn BlockDevice>,
    vfsmeta: FileSystemMeta,
    flags: VfsFlags,
    ext4: Ext4,
    driver_lock: AsyncMutex<()>,
    root: ManuallyDrop<LateInit<Arc<Ext4Inode>>>,
}

impl Ext4FileSystem {
    pub fn new(
        device: Arc<dyn BlockDevice>,
        flags: VfsFlags,
    ) -> Arc<Self> {
        let dev = device.metadata().dev_id;
        let fs = Arc::new(Ext4FileSystem {
            device: device.clone(),
            vfsmeta: FileSystemMeta::new(dev, "/dev/sda1", FileSystemType::EXT4),
            flags,
            ext4: Ext4::new(device),
            driver_lock: AsyncMutex::new(()),
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

    fn flags(&self) -> VfsFlags {
        self.flags
    }

    fn root(&self) -> Arc<dyn Inode> {
        self.root.clone()
    }
}
