use alloc::string::ToString;
use log::info;
use crate::driver::{DEVICES, Device};
use crate::fs::fat32::FAT32FileSystem;
use crate::fs::ffi::VfsFlags;
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
    let root_dev = match DEVICES.read().get(&0) {
        Some(Device::Block(blk)) => blk.clone(),
        _ => return Err(BlockDeviceError("Missing root block device".to_string())),
    };
    let fs = block_on(FAT32FileSystem::new(root_dev, VfsFlags::empty()))?;
    info!("File systems initialized");
    Ok(())
}
