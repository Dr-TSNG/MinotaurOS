use crate::driver::Box;
use crate::driver::ffi::DEV_BLOCK_MMC;
use crate::driver::{BlockDevice, DeviceMeta};
use crate::result::SyscallResult;
use crate::sync::mutex::Mutex;
use alloc::string::ToString;
use async_trait::async_trait;
use core::slice::{from_raw_parts, from_raw_parts_mut};
use crate::arch::{kvaddr_to_paddr, VirtAddr};

const BLOCK_SIZE: usize = 512;

pub struct RamDisk{
    base_vaddr: VirtAddr,
}

impl RamDisk{
    pub fn new(base_vaddr: VirtAddr) -> Self{
        Self{
            base_vaddr,
        }
    }
    pub fn block_ref(&self,block_id: usize,len: usize) -> &[u8]{
        unsafe {
            from_raw_parts((self.base_vaddr.0 + block_id*BLOCK_SIZE) as *const u8,len)
        }
    }

    pub fn block_refmut(&self,block_id: usize,len: usize) -> &mut [u8]{
        unsafe {
            from_raw_parts_mut((self.base_vaddr.0 + block_id*BLOCK_SIZE) as *mut u8 , len)
        }
    }
}

pub struct Disk{
    metadata: DeviceMeta,
    disk: Mutex<RamDisk>,
}

impl Disk{
    pub fn new(base_vaddr: VirtAddr) -> Self{
        Self{
            metadata: DeviceMeta::new(DEV_BLOCK_MMC,0,"disk".to_string()),
            disk: Mutex::new(RamDisk::new(base_vaddr)),
        }
    }
}

#[async_trait]
impl BlockDevice for Disk{
    fn metadata(&self) -> &DeviceMeta {
        &self.metadata
    }

    fn sector_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn dev_size(&self) -> usize {
        512 * 1024 * 1024
    }

    fn init(&self) {

    }

    async fn read_block(&self, block_id: usize, buf: &mut [u8]) -> SyscallResult {
        let blk = self.disk.lock();
        buf.copy_from_slice(blk.block_ref(block_id,buf.len()));
        Ok(())
    }

    async fn write_block(&self, block_id: usize, buf: &[u8]) -> SyscallResult {
        let blk = self.disk.lock();
        blk.block_refmut(block_id,buf.len()).copy_from_slice(buf);
        Ok(())
    }
}

