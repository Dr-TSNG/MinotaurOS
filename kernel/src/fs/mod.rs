use alloc::sync::Arc;
use log::info;
use crate::driver::{DEVICES, Device, BlockDevice};
use crate::fs::fat32::FAT32FileSystem;
use crate::fs::ffi::VfsFlags;
use crate::fs::file_system::MountNamespace;
use crate::result::SyscallResult;
use crate::sync::block_on;

pub mod block_cache;
pub mod devfs;
pub mod fat32;
pub mod fd;
pub mod ffi;
pub mod file;
pub mod file_system;
pub mod inode;
pub mod path;
pub mod page_cache;
pub mod pipe;

pub fn init() -> SyscallResult<Arc<MountNamespace>> {
    let mut root_dev = None;
    for device in DEVICES.read().values() {
        if let Device::Block(blk) = device {
            root_dev = Some(blk.clone());
            break;
        }
    }
    let root_dev = root_dev.expect("Missing root block device");
    let mnt_ns = block_on(async_init(root_dev))?;
    info!("File systems initialized");
    path::path_test();
    Ok(mnt_ns)
}

async fn async_init(root_dev: Arc<dyn BlockDevice>) -> SyscallResult<Arc<MountNamespace>> {
    let root_fs = FAT32FileSystem::new(root_dev, VfsFlags::empty()).await?;
    let mnt_ns = Arc::new(MountNamespace::new(root_fs));
    Ok(mnt_ns)
}
