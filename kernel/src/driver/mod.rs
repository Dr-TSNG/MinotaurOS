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

use crate::result::MosResult;
use crate::sync::mutex::{Mutex, RwLock};

pub static DEVICES: RwLock<BTreeMap<usize, Arc<dyn Device>>> = RwLock::new(BTreeMap::new());

static DEV_ID_ALLOCATOR: Mutex<IdAllocator> = Mutex::new(IdAllocator::new());

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

pub trait Device: Send + Sync {
    fn metadata(&self) -> &DeviceMeta;
}

/// 块设备
#[async_trait]
pub trait BlockDevice: Device {
    /// 从块设备读取数据
    async fn read_block(&self, block_id: usize, buf: &mut [u8]) -> MosResult;

    /// 向块设备写入数据
    async fn write_block(&self, block_id: usize, buf: &[u8]) -> MosResult;
}

pub fn init() -> MosResult {
    init_board()?;
    info!("Drivers initialized");
    Ok(())
}
