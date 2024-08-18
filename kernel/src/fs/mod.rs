use alloc::sync::Arc;
use log::info;
use crate::driver::{DEVICES, Device};
use crate::fs::ext4::Ext4FileSystem;
use crate::fs::ffi::VfsFlags;
use crate::fs::file_system::MountNamespace;
use crate::println;
use crate::result::SyscallResult;

pub mod devfs;
pub mod ext4;
// pub mod fat32;
pub mod fd;
pub mod ffi;
pub mod file;
pub mod file_system;
pub mod inode;
// pub mod inode_cache;
pub mod path;
pub mod page_cache;
pub mod pipe;
pub mod procfs;
pub mod tmpfs;
mod inotify;

pub fn init() -> SyscallResult<Arc<MountNamespace>> {
    println!("fs_init");
    let mut root_dev = None;
    for device in DEVICES.lock().values() {
        if let Device::Block(blk) = device {
            root_dev = Some(blk.clone());
            break;
        }
    }
    let root_dev = root_dev.expect("Missing root block device");
    println!("root_dev getted");

    let root_fs = Ext4FileSystem::new(root_dev, VfsFlags::ST_WRITE | VfsFlags::ST_RELATIME);
    let mnt_ns = Arc::new(MountNamespace::new(root_fs));

    info!("File systems initialized");
    path::path_test();
    Ok(mnt_ns)
}
