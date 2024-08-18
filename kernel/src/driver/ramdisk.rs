use crate::driver::Box;
use crate::driver::ffi::DEV_BLOCK_MMC;
use crate::driver::{BlockDevice, DeviceMeta};
use crate::result::SyscallResult;
use crate::sync::mutex::AsyncMutex;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::iter::repeat_with;
use core::ops::Add;
use async_trait::async_trait;
use crate::arch::VirtAddr;

const BLOCK_SIZE: usize = 4096;

pub struct RamDisk {
    metadata: DeviceMeta,
    base_addr: VirtAddr,
    segments: Vec<AsyncMutex<()>>,
}

impl RamDisk {
    pub fn new(base_addr: VirtAddr, size: usize) -> Self {
        Self {
            metadata: DeviceMeta::new(DEV_BLOCK_MMC, 0, "disk".to_string()),
            base_addr,
            segments: Vec::from_iter(
                repeat_with(|| AsyncMutex::new(())).take(size / BLOCK_SIZE)
            ),
        }
    }
}

#[async_trait]
impl BlockDevice for RamDisk {
    fn metadata(&self) -> &DeviceMeta {
        &self.metadata
    }

    fn sector_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn dev_size(&self) -> usize {
        512 * 1024 * 1024
    }

    fn init(&self) {}

    async fn read_block(&self, block_id: usize, buf: &mut [u8]) -> SyscallResult {
        let _guard = self.segments[block_id].lock();
        let blk = self.base_addr.add(block_id * BLOCK_SIZE).as_ptr();
        unsafe {
            buf.copy_from_slice(core::slice::from_raw_parts(blk, BLOCK_SIZE));
        }
        Ok(())
    }

    async fn write_block(&self, block_id: usize, buf: &[u8]) -> SyscallResult {
        let _guard = self.segments[block_id].lock();
        let blk = self.base_addr.add(block_id * BLOCK_SIZE).as_ptr();
        unsafe {
            core::slice::from_raw_parts_mut(blk, BLOCK_SIZE).copy_from_slice(buf);
        }
        Ok(())
    }
}

