use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::ptr::NonNull;
use log::info;
use virtio_drivers::{BufferDirection, Hal};
use crate::arch::{kvaddr_to_paddr, paddr_to_kvaddr, PhysAddr, PhysPageNum, VirtAddr};
use crate::driver::Device;
use crate::driver::virtio::VirtIOBlock;
use crate::mm::allocator::{alloc_kernel_frames, HeapFrameTracker};
use crate::result::MosResult;
use crate::sync::mutex::IrqMutex;

pub mod virtio;

static VIRTIO_FRAMES: IrqMutex<BTreeMap<PhysPageNum, HeapFrameTracker>> = IrqMutex::new(BTreeMap::new());

pub struct VirtioHal;

unsafe impl Hal for VirtioHal {
    fn dma_alloc(
        pages: usize,
        _direction: BufferDirection,
    ) -> (virtio_drivers::PhysAddr, NonNull<u8>) {
        let tracker = alloc_kernel_frames(pages).unwrap();
        let base_ppn = tracker.ppn;
        VIRTIO_FRAMES.lock().insert(base_ppn, tracker);
        let paddr = PhysAddr::from(base_ppn);
        let vaddr = unsafe {
            NonNull::new_unchecked(paddr_to_kvaddr(paddr).0 as *mut u8)
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
        NonNull::new_unchecked(paddr_to_kvaddr(PhysAddr::from(paddr)).0 as *mut u8)
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

pub fn init_board() -> MosResult {
    let virtio_blk = Arc::new(VirtIOBlock::new()?);
    let virtio_blk = Device::Block(virtio_blk);
    let virtio_dev_id = virtio_blk.metadata().dev_id;
    super::DEVICES.write().insert(virtio_dev_id, virtio_blk);
    info!("VIRTIO0 block initialized");
    Ok(())
}
