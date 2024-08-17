use core::cmp::max;
use buddy_system_allocator::FrameAllocator;
use log::warn;
use crate::arch::{kvaddr_to_paddr, PAGE_SIZE, PhysPageNum};
use crate::config::linkage_ekernel;
use crate::driver::GLOBAL_MAPPINGS;
use crate::println;
use crate::result::{Errno, SyscallResult};
use crate::sync::mutex::IrqMutex;
use crate::sync::once::LateInit;

static USER_ALLOCATOR: LateInit<IrqMutex<UserFrameAllocator>> = LateInit::new();

pub struct UserFrameTracker {
    pub ppn: PhysPageNum,
    pub pages: usize,
}

impl Drop for UserFrameTracker {
    fn drop(&mut self) {
        USER_ALLOCATOR.lock().dealloc(&self);
    }
}

struct UserFrameAllocator(FrameAllocator, usize, usize);

impl UserFrameAllocator {
    fn new() -> Self {
        Self(FrameAllocator::new(), 0, 0)
    }

    fn add_frame(&mut self, start: PhysPageNum, end: PhysPageNum) {
        self.0.add_frame(start.0, end.0);
        self.1 += end - start;
    }

    fn alloc(&mut self, pages: usize) -> SyscallResult<UserFrameTracker> {
        match self.0.alloc(pages) {
            Some(ppn) => {
                self.2 += pages;
                Ok(UserFrameTracker { ppn: PhysPageNum(ppn), pages })
            }
            None => {
                warn!("[UserFrameAllocator] Out of memory for {} pages", pages);
                Err(Errno::ENOSPC)
            }
        }
    }

    fn dealloc(&mut self, tracker: &UserFrameTracker) {
        self.0.dealloc(tracker.ppn.0, tracker.pages);
        self.2 -= tracker.pages;
    }
}

/// 分配连续的用户页帧
///
/// SAFETY: 保证分配的页已经清零
pub fn alloc_user_frames(pages: usize) -> SyscallResult<UserFrameTracker> {
    let tracker = USER_ALLOCATOR.lock().alloc(pages)?;
    for ppn in tracker.ppn..tracker.ppn + pages {
        ppn.byte_array().fill(0);
    }
    Ok(tracker)
}

pub fn free_user_memory() -> usize {
    let allocator = USER_ALLOCATOR.lock();
    (allocator.1 - allocator.2) * PAGE_SIZE
}

pub fn init() {
    let mut allocator = UserFrameAllocator::new();
    for map in GLOBAL_MAPPINGS.iter() {
        if map.name.starts_with("[memory") {
            let start = max(map.phys_start, kvaddr_to_paddr(linkage_ekernel()));
            let end = map.phys_end();
            allocator.add_frame(start.into(), end.into());
            println!("[kernel] Initialize user memory: {:?} - {:?}", start, end);
        }
    }
    USER_ALLOCATOR.init(IrqMutex::new(allocator));
}
