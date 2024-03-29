use alloc::boxed::Box;
use alloc::string::ToString;
use async_trait::async_trait;
use crate::driver::{BlockDevice, DeviceMeta, VirtioHal};
use crate::sync::mutex::IrqMutex;
use virtio_drivers::device::blk::VirtIOBlk;
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};
use crate::board::GLOBAL_MAPPINGS;
use crate::result::MosError::BlockDeviceError;
use crate::result::MosResult;

// TODO: Real async support
pub struct VirtIOBlock {
    metadata: DeviceMeta,
    block: IrqMutex<VirtIOBlk<VirtioHal, MmioTransport>>,
}

unsafe impl Send for VirtIOBlock {}

unsafe impl Sync for VirtIOBlock {}

#[async_trait]
impl BlockDevice for VirtIOBlock {
    fn metadata(&self) -> &DeviceMeta {
        &self.metadata
    }

    async fn read_block(&self, block_id: usize, buf: &mut [u8]) -> MosResult {
        self.block
            .lock()
            .read_blocks(block_id, buf)
            .map_err(|e| BlockDeviceError(e.to_string()))
    }

    async fn write_block(&self, block_id: usize, buf: &[u8]) -> MosResult {
        self.block
            .lock()
            .write_blocks(block_id, buf)
            .map_err(|e| BlockDeviceError(e.to_string()))
    }
}

impl VirtIOBlock {
    pub fn new() -> MosResult<Self> {
        let map = GLOBAL_MAPPINGS.iter().find(|m| m.name == "[virtio0]")
            .ok_or(BlockDeviceError("No VIRTIO0 device".to_string()))?;
        unsafe {
            let header = &mut *(map.virt_start.0 as *mut VirtIOHeader);
            let transport = MmioTransport::new(header.into())
                .map_err(|e| BlockDeviceError(e.to_string()))?;
            let block = VirtIOBlk::<VirtioHal, MmioTransport>::new(transport)
                .map_err(|e| BlockDeviceError(e.to_string()))?;
            let block = Self {
                metadata: DeviceMeta::new("VIRTIO0".to_string()),
                block: IrqMutex::new(block),
            };
            Ok(block)
        }
    }
}
