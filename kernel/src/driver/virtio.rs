use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::sync::Arc;
use core::ptr::NonNull;
use async_trait::async_trait;
use log::error;
use crate::driver::{BlockDevice, DeviceMeta};
use crate::sync::mutex::IrqMutex;
use virtio_drivers::device::blk::VirtIOBlk;
use virtio_drivers::{BufferDirection, Hal};
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};
use crate::arch::{kvaddr_to_paddr, paddr_to_kvaddr, PhysAddr, PhysPageNum, VirtAddr};
use crate::mm::allocator::{alloc_kernel_frames, HeapFrameTracker};
use crate::result::{Errno, SyscallResult};

static VIRTIO_FRAMES: IrqMutex<BTreeMap<PhysPageNum, HeapFrameTracker>> = IrqMutex::new(BTreeMap::new());

pub struct VirtioHal;

unsafe impl Hal for VirtioHal {
    fn dma_alloc(
        pages: usize,
        _direction: BufferDirection,
    ) -> (virtio_drivers::PhysAddr, NonNull<u8>) {
        let tracker = alloc_kernel_frames(pages);
        let base_ppn = tracker.ppn;
        VIRTIO_FRAMES.lock().insert(base_ppn, tracker);
        let paddr = PhysAddr::from(base_ppn);
        let vaddr = unsafe {
            NonNull::new_unchecked(paddr_to_kvaddr(paddr).as_ptr())
        };
        (paddr.0, vaddr)
    }

    unsafe fn dma_dealloc(
        paddr: virtio_drivers::PhysAddr,
        _vaddr: NonNull<u8>,
        _pages: usize,
    ) -> i32 {
        let base_ppn = PhysPageNum::from(PhysAddr(paddr));
        VIRTIO_FRAMES.lock().remove(&base_ppn).unwrap();
        0
    }

    unsafe fn mmio_phys_to_virt(
        paddr: virtio_drivers::PhysAddr,
        _size: usize,
    ) -> NonNull<u8> {
        NonNull::new_unchecked(paddr_to_kvaddr(PhysAddr(paddr)).as_ptr())
    }

    unsafe fn share(
        buffer: NonNull<[u8]>,
        _direction: BufferDirection,
    ) -> virtio_drivers::PhysAddr {
        kvaddr_to_paddr(VirtAddr(buffer.as_ptr().addr())).0
    }

    unsafe fn unshare(
        _paddr: virtio_drivers::PhysAddr,
        _buffer: NonNull<[u8]>,
        _direction: BufferDirection,
    ) {}
}

// TODO: Real async support
pub struct VirtIODevice {
    metadata: DeviceMeta,
    block: IrqMutex<VirtIOBlk<VirtioHal, MmioTransport>>,
}

unsafe impl Send for VirtIODevice {}

unsafe impl Sync for VirtIODevice {}

#[async_trait]
impl BlockDevice for VirtIODevice {
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

impl VirtIODevice {
    pub fn new(virt_addr: VirtAddr) -> SyscallResult<Arc<Self>> {
        unsafe {
            let header = &mut *(virt_addr.0 as *mut VirtIOHeader);
            let transport = MmioTransport::new(header.into())
                .inspect_err(|e| error!("VirtIO error: {:?}", e))
                .map_err(|_| Errno::ENODEV)?;
            let block = VirtIOBlk::<VirtioHal, MmioTransport>::new(transport)
                .inspect_err(|e| error!("VirtIO error: {:?}", e))
                .map_err(|_| Errno::ENODEV)?;
            let block = Self {
                metadata: DeviceMeta::new("virtio".to_string()),
                block: IrqMutex::new(block),
            };
            Ok(Arc::new(block))
        }
    }
}
