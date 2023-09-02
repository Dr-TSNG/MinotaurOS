use alloc::vec;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::ptr::NonNull;
use common::arch::{PAGE_SIZE, PhysAddr, PhysPageNum};
use common::println;
use crate::board::PHYS_MEMORY;
use crate::mm::allocator::Allocator;
use crate::result::{MosError, MosResult};

static USER_ALLOCATOR: Allocator = Allocator::empty();

pub struct UserFrameTracker {
    pub ppn: PhysPageNum,
    pub pages: usize,
}

impl Drop for UserFrameTracker {
    fn drop(&mut self) {
        dealloc_user_frames(&self);
    }
}

pub fn alloc_user_frames(pages: usize) -> MosResult<Vec<UserFrameTracker>> {
    let mut allocator = USER_ALLOCATOR.0.lock();
    let mut trackers = vec![];
    for _ in 0..pages {
        let ppn = allocator.alloc(Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).unwrap())
            .map(|pa| PhysPageNum::from(PhysAddr(pa.as_ptr() as usize)))
            .map_err(|_| MosError::OutOfMemory)?;
        trackers.push(UserFrameTracker { ppn, pages: 1 });
    }
    Ok(trackers)
}

pub fn alloc_user_frames_cont(pages: usize) -> MosResult<UserFrameTracker> {
    let ppn = USER_ALLOCATOR.0.lock()
        .alloc(Layout::from_size_align(pages * PAGE_SIZE, PAGE_SIZE).unwrap())
        .map(|pa| PhysPageNum::from(PhysAddr(pa.as_ptr() as usize)))
        .map_err(|_| MosError::OutOfMemory)?;
    let tracker = UserFrameTracker { ppn, pages };
    Ok(tracker)
}

fn dealloc_user_frames(tracker: &UserFrameTracker) {
    let ptr = PhysAddr::from(tracker.ppn).0 as *mut u8;
    let ptr = NonNull::new(ptr).unwrap();
    USER_ALLOCATOR.0.lock()
        .dealloc(ptr, Layout::from_size_align(tracker.pages * PAGE_SIZE, PAGE_SIZE).unwrap());
}

pub fn init() {
    let mut allocator = USER_ALLOCATOR.0.lock();
    unsafe {
        PHYS_MEMORY.iter().for_each(|&(start, end)| {
            println!("[kernel] Initialize user memory: {:?} - {:?}", start, end);
            allocator.add_to_heap(start.0, end.0);
        });
    }
}
