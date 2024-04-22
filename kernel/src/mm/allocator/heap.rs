use core::alloc::{GlobalAlloc, Layout};
use core::ptr::NonNull;
use buddy_system_allocator::Heap;
use crate::arch::{kvpn_to_ppn, PAGE_SIZE, PhysPageNum, ppn_to_kvpn, VirtAddr, VirtPageNum};
use crate::config::KERNEL_HEAP_SIZE;
use crate::println;
use crate::sync::mutex::IrqMutex;

#[global_allocator]
static KERNEL_HEAP: HeapAllocator = HeapAllocator::empty();

#[link_section = ".bss.heap"]
static mut HEAP_SPACE: [u8; KERNEL_HEAP_SIZE] = [0; KERNEL_HEAP_SIZE];

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
        dealloc_kernel_pages(&self);
    }
}

struct HeapAllocator(IrqMutex<Heap<32>>);

impl HeapAllocator {
    const fn empty() -> Self {
        HeapAllocator(IrqMutex::new(Heap::empty()))
    }
}

unsafe impl GlobalAlloc for HeapAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.0.lock().alloc(layout)
            .map_or(VirtAddr(0).as_ptr(), |va| va.as_ptr())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.0.lock().dealloc(NonNull::new_unchecked(ptr), layout);
    }
}

/// 分配连续的内核页帧
/// 
/// SAFETY: 保证分配的页已经清零
pub fn alloc_kernel_frames(pages: usize) -> HeapFrameTracker {
    let vpn = KERNEL_HEAP.0.lock()
        .alloc(Layout::from_size_align(pages * PAGE_SIZE, PAGE_SIZE).unwrap())
        .map(|va| VirtPageNum::from(VirtAddr(va.as_ptr() as usize)))
        .expect("[HeapAllocator] Out of memory");
    let ppn = kvpn_to_ppn(vpn);
    ppn.byte_array().fill(0);
    HeapFrameTracker { ppn, pages }
}

fn dealloc_kernel_pages(tracker: &HeapFrameTracker) {
    let vpn = ppn_to_kvpn(tracker.ppn);
    let ptr = unsafe { VirtAddr::from(vpn).as_ptr() };
    let ptr = NonNull::new(ptr).unwrap();
    KERNEL_HEAP.0.lock()
        .dealloc(ptr, Layout::from_size_align(tracker.pages * PAGE_SIZE, PAGE_SIZE).unwrap());
}

pub fn init() {
    unsafe {
        let start = HEAP_SPACE.as_ptr();
        let end = start.add(KERNEL_HEAP_SIZE);
        KERNEL_HEAP.0.lock().add_to_heap(start as usize, end as usize);
        println!("[kernel] Initialize kernel heap: {:?} - {:?}", start, end);
    }
}
