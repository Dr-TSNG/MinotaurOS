#[cfg(feature = "board_qemu")]
mod qemu;

use alloc::sync::Arc;
use log::info;
#[cfg(feature = "board_qemu")]
pub use qemu::*;

use crate::driver::virtio::VirtIOBlock;
use crate::result::MosResult;
use crate::sync::mutex::Mutex;

/// 块设备
pub trait BlockDevice: Send + Sync {
    /// Read data form block to buffer
    fn read_block(&self, block_id: usize, buf: &mut [u8]) -> MosResult;
    /// Write data from buffer to block
    fn write_block(&self, block_id: usize, buf: &[u8]) -> MosResult;
}

pub static BLOCK_DEVICE: Mutex<Option<Arc<dyn BlockDevice>>> = Mutex::new(None);

pub fn init() -> MosResult {
    #[cfg(feature = "board_qemu")]
    *BLOCK_DEVICE.lock() = Some(Arc::new(VirtIOBlock::new()?));
    info!("Drivers initialized");
    Ok(())
}
