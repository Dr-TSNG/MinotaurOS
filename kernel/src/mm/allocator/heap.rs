use core::alloc::{GlobalAlloc, Layout};
use core::ptr::NonNull;
use buddy_system_allocator::Heap;
use spin::Mutex;
use common::arch::{PAGE_SIZE, VirtAddr, VirtPageNum};
use common::println;
use crate::board::KERNEL_HEAP_END;
use crate::result::{MosError, MosResult};

#[global_allocator]
static KERNEL_HEAP: KernelHeap = KernelHeap::empty();

#[alloc_error_handler]
pub fn handle_alloc_error(layout: Layout) -> ! {
    panic!("Failed to allocate, layout = {:?}", layout);
}

struct KernelHeap(Mutex<Heap<32>>);

impl KernelHeap {
    pub const fn empty() -> Self {
        KernelHeap(Mutex::new(Heap::empty()))
    }
}

unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.0.lock().alloc(layout)
            .map_or(0 as *mut u8, |va| va.as_ptr())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.0.lock().dealloc(NonNull::new_unchecked(ptr), layout);
    }
}

pub fn alloc_kernel_pages(pages: usize) -> MosResult<VirtPageNum> {
    KERNEL_HEAP.0.lock()
        .alloc(Layout::from_size_align(pages * PAGE_SIZE, PAGE_SIZE).unwrap())
        .map(|va| VirtPageNum::from(VirtAddr(va.as_ptr() as usize)))
        .map_err(|_| MosError::OutOfMemory)
}

pub fn dealloc_kernel_pages(vpn: VirtPageNum, pages: usize) -> MosResult {
    let ptr = VirtAddr::from(vpn).0 as *mut u8;
    let ptr = NonNull::new(ptr).ok_or(MosError::InvalidAddress)?;
    KERNEL_HEAP.0.lock()
        .dealloc(ptr, Layout::from_size_align(pages * PAGE_SIZE, PAGE_SIZE).unwrap());
    Ok(())
}

pub fn init() {
    extern "C" {
        fn ekernel();
    }
    let kernel_heap_start = VirtAddr(ekernel as usize);
    unsafe {
        println!("[kernel] Initialize kernel heap: {} - {}", kernel_heap_start, KERNEL_HEAP_END);
        KERNEL_HEAP.0.lock()
            .add_to_heap(kernel_heap_start.0, KERNEL_HEAP_END.0);
    }
}
