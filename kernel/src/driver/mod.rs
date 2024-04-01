#[cfg(feature = "board_qemu")]
mod qemu;

#[cfg(feature = "board_qemu")]
pub use qemu::*;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use async_trait::async_trait;
use log::info;
use crate::mm::allocator::IdAllocator;

use crate::result::SyscallResult;
use crate::sync::mutex::{Mutex, RwLock};

pub static DEVICES: RwLock<BTreeMap<usize, Device>> = RwLock::new(BTreeMap::new());

static DEV_ID_ALLOCATOR: Mutex<IdAllocator> = Mutex::new(IdAllocator::new(1));

pub enum Device {
    Block(Arc<dyn BlockDevice>),
}

impl Device {
    pub fn metadata(&self) -> &DeviceMeta {
        match self {
            Device::Block(dev) => dev.metadata(),
        }
    }
}

pub struct DeviceMeta {
    pub dev_id: usize,
    pub dev_name: String,
}

impl DeviceMeta {
    fn new(dev_name: String) -> DeviceMeta {
        Self {
            dev_id: DEV_ID_ALLOCATOR.lock().alloc(),
            dev_name,
        }
    }
}

/// 块设备
#[async_trait]
pub trait BlockDevice: Send + Sync {
    /// 块元数据
    fn metadata(&self) -> &DeviceMeta;
    
    /// 从块设备读取数据
    async fn read_block(&self, block_id: usize, buf: &mut [u8]) -> SyscallResult;

    /// 向块设备写入数据
    async fn write_block(&self, block_id: usize, buf: &[u8]) -> SyscallResult;
}

pub fn init() -> SyscallResult {
    init_board()?;
    info!("Drivers initialized");
    Ok(())
}
