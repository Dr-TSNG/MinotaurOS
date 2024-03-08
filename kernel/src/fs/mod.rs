use alloc::string::ToString;
use alloc::sync::Arc;
use log::info;
use crate::driver::{DEVICES, Device, BlockDevice};
use crate::fs::fat32::FAT32FileSystem;
use crate::fs::ffi::VfsFlags;
use crate::fs::file_system::MountNamespace;
use crate::result::MosError::BlockDeviceError;
use crate::result::MosResult;
use crate::sync::block_on;

pub mod block_cache;
pub mod devfs;
pub mod fat32;
pub mod fd;
pub mod ffi;
pub mod file;
pub mod file_system;
pub mod inode;

pub fn init() -> MosResult<Arc<MountNamespace>> {
    let root_dev = match DEVICES.read().get(&1) {
        Some(Device::Block(blk)) => blk.clone(),
        _ => return Err(BlockDeviceError("Missing root block device".to_string())),
    };
    let mnt_ns = block_on(async_init(root_dev))?;
    info!("File systems initialized");
    Ok(mnt_ns)
}

async fn async_init(root_dev: Arc<dyn BlockDevice>) -> MosResult<Arc<MountNamespace>> {
    let root_fs = FAT32FileSystem::new(root_dev, VfsFlags::empty()).await?;
    let mnt_ns = Arc::new(MountNamespace::new(root_fs));
    Ok(mnt_ns)
}
