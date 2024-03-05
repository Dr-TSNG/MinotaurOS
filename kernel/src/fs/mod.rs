use alloc::string::ToString;
use alloc::sync::Arc;
use log::{debug, info};
use crate::driver::{DEVICES, Device, BlockDevice};
use crate::fs::fat32::FAT32FileSystem;
use crate::fs::ffi::VfsFlags;
use crate::fs::file_system::FileSystem;
use crate::result::MosError::BlockDeviceError;
use crate::result::MosResult;
use crate::sync::block_on;
use crate::sync::once::LateInit;

pub mod block_cache;
pub mod devfs;
pub mod fat32;
pub mod fd;
pub mod ffi;
pub mod file;
pub mod file_system;
pub mod inode;

pub static ROOT_FS: LateInit<Arc<dyn FileSystem>> = LateInit::new();

pub fn init() -> MosResult {
    let root_dev = match DEVICES.read().get(&0) {
        Some(Device::Block(blk)) => blk.clone(),
        _ => return Err(BlockDeviceError("Missing root block device".to_string())),
    };
    block_on(async_init(root_dev))?;
    info!("File systems initialized");
    Ok(())
}

async fn async_init(root_dev: Arc<dyn BlockDevice>) -> MosResult {
    ROOT_FS.init(FAT32FileSystem::new(root_dev, VfsFlags::empty()).await?);
    let inode = ROOT_FS.clone().root().await?;
    let mut i = 0;
    while let Ok(f) = inode.clone().list(i).await {
        debug!("ls: {}", f.metadata().inner.lock().name);
        i += 1;
    }
    Ok(())
}
