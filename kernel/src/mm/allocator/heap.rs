use core::alloc::{GlobalAlloc, Layout};
use core::ptr::NonNull;
use buddy_system_allocator::Heap;
use log::trace;
use spin::Mutex;
use common::arch::{kvpn_to_ppn, PAGE_SIZE, PhysPageNum, ppn_to_kvpn, VirtAddr, VirtPageNum};
use common::println;
use crate::board::KERNEL_HEAP_END;
use crate::result::{MosError, MosResult};

#[global_allocator]
static KERNEL_HEAP: HeapAllocator = HeapAllocator::empty();

#[alloc_error_handler]
pub fn handle_alloc_error(layout: Layout) -> ! {
    panic!("Failed to allocate, layout = {:?}", layout);
}

pub struct HeapFrameTracker {
    pub ppn: PhysPageNum,
    pub pages: usize,
}

impl Drop for HeapFrameTracker {
    fn drop(&mut self) {
        trace!("HeapFrameTracker: dealloc kernel frame {:?} for {} pages", self.ppn, self.pages);
        dealloc_kernel_pages(&self);
    }
}

struct HeapAllocator(Mutex<Heap<32>>);

impl HeapAllocator {
    const fn empty() -> Self {
        HeapAllocator(Mutex::new(Heap::empty()))
    }
}

unsafe impl GlobalAlloc for HeapAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.0.lock().alloc(layout)
            .map_or(0 as *mut u8, |va| va.as_ptr())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.0.lock().dealloc(NonNull::new_unchecked(ptr), layout);
    }
}

pub fn alloc_kernel_frames(pages: usize) -> MosResult<HeapFrameTracker> {
    let vpn = KERNEL_HEAP.0.lock()
        .alloc(Layout::from_size_align(pages * PAGE_SIZE, PAGE_SIZE).unwrap())
        .map(|va| VirtPageNum::from(VirtAddr(va.as_ptr() as usize)))
        .map_err(|_| MosError::OutOfMemory)?;
    let tracker = HeapFrameTracker {
        ppn: kvpn_to_ppn(vpn),
        pages,
    };
    Ok(tracker)
}

fn dealloc_kernel_pages(tracker: &HeapFrameTracker) {
    let vpn = ppn_to_kvpn(tracker.ppn);
    let ptr = VirtAddr::from(vpn).0 as *mut u8;
    let ptr = NonNull::new(ptr).unwrap();
    KERNEL_HEAP.0.lock()
        .dealloc(ptr, Layout::from_size_align(tracker.pages * PAGE_SIZE, PAGE_SIZE).unwrap());
}

pub fn init() {
    extern "C" {
        fn ekernel();
    }
    let kernel_heap_start = VirtAddr(ekernel as usize);
    unsafe {
        println!("[kernel] Initialize kernel heap: {:?} - {:?}", kernel_heap_start, KERNEL_HEAP_END);
        KERNEL_HEAP.0.lock()
            .add_to_heap(kernel_heap_start.0, KERNEL_HEAP_END.0);
    }
}
