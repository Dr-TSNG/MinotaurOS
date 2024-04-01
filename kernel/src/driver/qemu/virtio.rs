use alloc::boxed::Box;
use alloc::string::ToString;
use async_trait::async_trait;
use log::error;
use crate::driver::{BlockDevice, DeviceMeta, VirtioHal};
use crate::sync::mutex::IrqMutex;
use virtio_drivers::device::blk::VirtIOBlk;
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};
use crate::board::GLOBAL_MAPPINGS;
use crate::result::{Errno, SyscallResult};

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

    async fn read_block(&self, block_id: usize, buf: &mut [u8]) -> SyscallResult {
        self.block
            .lock()
            .read_blocks(block_id, buf)
            .inspect_err(|e| error!("VirtIOBlock read error: {:?}", e))
            .map_err(|_| Errno::EIO)
    }

    async fn write_block(&self, block_id: usize, buf: &[u8]) -> SyscallResult {
        self.block
            .lock()
            .write_blocks(block_id, buf)
            .inspect_err(|e| error!("VirtIOBlock write error: {:?}", e))
            .map_err(|_| Errno::EIO)
    }
}

impl VirtIOBlock {
    pub fn new() -> SyscallResult<Self> {
        let map = GLOBAL_MAPPINGS.iter().find(|m| m.name == "[virtio0]")
            .ok_or(Errno::ENODEV)?;
        unsafe {
            let header = &mut *(map.virt_start.0 as *mut VirtIOHeader);
            let transport = MmioTransport::new(header.into())
                .inspect_err(|e| error!("VirtIO error: {:?}", e))
                .map_err(|_| Errno::ENODEV)?;
            let block = VirtIOBlk::<VirtioHal, MmioTransport>::new(transport)
                .inspect_err(|e| error!("VirtIO error: {:?}", e))
                .map_err(|_| Errno::ENODEV)?;
            let block = Self {
                metadata: DeviceMeta::new("VIRTIO0".to_string()),
                block: IrqMutex::new(block),
            };
            Ok(block)
        }
    }
}
