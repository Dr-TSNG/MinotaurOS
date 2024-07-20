use alloc::collections::BTreeMap;
use core::ptr::NonNull;
use virtio_drivers::{BufferDirection, Hal};
use crate::arch::{kvaddr_to_paddr, paddr_to_kvaddr, PhysAddr, PhysPageNum, VirtAddr};
use crate::mm::allocator::{alloc_kernel_frames, HeapFrameTracker};
use crate::sync::mutex::IrqMutex;

pub mod blk;
pub mod net;

static VIRTIO_FRAMES: IrqMutex<BTreeMap<PhysPageNum, HeapFrameTracker>> = IrqMutex::new(BTreeMap::new());

struct VirtioHal;

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
