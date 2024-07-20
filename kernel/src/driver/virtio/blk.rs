use alloc::boxed::Box;
use alloc::string::ToString;
use async_trait::async_trait;
use log::error;
use crate::driver::{BlockDevice, DeviceMeta};
use crate::sync::mutex::IrqMutex;
use virtio_drivers::device::blk::{SECTOR_SIZE, VirtIOBlk};
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};
use crate::arch::VirtAddr;
use crate::driver::virtio::VirtioHal;
use crate::result::{Errno, SyscallResult};
use crate::sync::once::LateInit;

type Blk = VirtIOBlk<VirtioHal, MmioTransport>;

// TODO: Real async support
pub struct VirtIOBlkDevice {
    metadata: DeviceMeta,
    base_addr: VirtAddr,
    block: LateInit<IrqMutex<Blk>>,
}

unsafe impl Send for VirtIOBlkDevice {}

unsafe impl Sync for VirtIOBlkDevice {}

#[async_trait]
impl BlockDevice for VirtIOBlkDevice {
    fn metadata(&self) -> &DeviceMeta {
        &self.metadata
    }

    fn sector_size(&self) -> usize {
        SECTOR_SIZE
    }

    fn dev_size(&self) -> usize {
        SECTOR_SIZE * self.block.lock().capacity() as usize
    }

    fn init(&self) {
        unsafe {
            let header = self.base_addr.as_ptr().cast::<VirtIOHeader>().as_mut().unwrap();
            let transport = MmioTransport::new(header.into()).unwrap();
            let block = Blk::new(transport).unwrap();
            self.block.init(IrqMutex::new(block));
        }
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

impl VirtIOBlkDevice {
    pub fn new(base_addr: VirtAddr) -> Self {
        Self {
            metadata: DeviceMeta::new("virtio-blk".to_string()),
            base_addr,
            block: LateInit::new(),
        }
    }
}
