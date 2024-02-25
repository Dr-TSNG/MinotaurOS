use alloc::string::ToString;
use crate::driver::{BlockDevice, VirtioHal};
use crate::sync::mutex::IrqMutex;
use virtio_drivers::device::blk::VirtIOBlk;
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};
use crate::board::GLOBAL_MAPPINGS;
use crate::result::MosError::BlockDeviceError;
use crate::result::MosResult;

pub struct VirtIOBlock(IrqMutex<VirtIOBlk<VirtioHal, MmioTransport>>);

unsafe impl Send for VirtIOBlock {}

unsafe impl Sync for VirtIOBlock {}

impl BlockDevice for VirtIOBlock {
    fn read_block(&self, block_id: usize, buf: &mut [u8]) -> MosResult {
        self.0
            .lock()
            .read_blocks(block_id, buf)
            .map_err(|e| BlockDeviceError(e.to_string()))
    }
    fn write_block(&self, block_id: usize, buf: &[u8]) -> MosResult {
        self.0
            .lock()
            .write_blocks(block_id, buf)
            .map_err(|e| BlockDeviceError(e.to_string()))
    }
}

impl VirtIOBlock {
    pub fn new() -> MosResult<Self> {
        let map = GLOBAL_MAPPINGS.iter().find(|m| m.name == "VIRTIO0")
            .ok_or(BlockDeviceError("No VIRTIO0 device".to_string()))?;
        unsafe {
            let header = &mut *(map.virt_start.0 as *mut VirtIOHeader);
            let transport = MmioTransport::new(header.into())
                .map_err(|e| BlockDeviceError(e.to_string()))?;
            let blk = VirtIOBlk::<VirtioHal, MmioTransport>::new(transport)
                .map_err(|e| BlockDeviceError(e.to_string()))?;
            Ok(Self(IrqMutex::new(blk)))
        }
    }
}
