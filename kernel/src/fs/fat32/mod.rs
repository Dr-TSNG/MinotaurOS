use alloc::sync::Arc;
use log::info;
use crate::driver::BlockDevice;
use crate::fs::fat32::fat::FAT32Meta;
use crate::fs::file_system::{FileSystem, FileSystemMeta};
use crate::fs::inode::Inode;
use crate::result::{MosResult, SyscallResult};

mod inode;
mod boot_sector;
mod fat;

const PRELOAD_SECTOR_SIZE: usize = 512;

const BOOT_SECTOR_ID: usize = 0;

pub struct FAT32FileSystem {
    device: Arc<dyn BlockDevice>,
    metadata: FileSystemMeta,
    fat32meta: FAT32Meta,
}

impl FAT32FileSystem {
    pub async fn new(
        device: Arc<dyn BlockDevice>,
        metadata: FileSystemMeta,
    ) -> MosResult<Self> {
        let mut boot_sector = [0; PRELOAD_SECTOR_SIZE];
        device.read_block(BOOT_SECTOR_ID, &mut boot_sector).await?;
        let fat32meta = FAT32Meta::new(&boot_sector)?;
        info!("FAT32 metadata: {:?}", fat32meta);
        let fs = FAT32FileSystem {
            device,
            metadata,
            fat32meta,
        };
        Ok(fs)
    }
}

impl FileSystem for FAT32FileSystem {
    fn metadata(&self) -> &FileSystemMeta {
        &self.metadata
    }

    fn root(&self) -> SyscallResult<Arc<dyn Inode>> {
        todo!()
    }
}
