use alloc::string::ToString;
use alloc::sync::Arc;
use log::info;
use crate::driver::{BLOCK_DEVICES, BlockDevice};
use crate::fs::fat32::FAT32FileSystem;
use crate::fs::ffi::VfsFlags;
use crate::fs::file_system::{FileSystemMeta, FileSystemType};
use crate::result::MosError::BlockDeviceError;
use crate::result::MosResult;
use crate::sync::block_on;

pub mod block_cache;
pub mod fat32;
pub mod ffi;
pub mod file;
pub mod file_system;
pub mod inode;

pub fn init() -> MosResult {
    let root_dev = BLOCK_DEVICES.read().get(&0)
        .map(Arc::clone)
        .ok_or(BlockDeviceError("Root device missing".to_string()))?;
    let fs = FAT32FileSystem::new(
        root_dev, FileSystemMeta::new(FileSystemType::FAT32, VfsFlags::empty()));
    let fs = block_on(fs)?;
    info!("File systems initialized");
    Ok(())
}
