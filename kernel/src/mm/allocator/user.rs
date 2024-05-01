use alloc::vec::Vec;
use core::cmp::max;
use bitvec_rs::BitVec;
use log::warn;
use crate::arch::{kvaddr_to_paddr, PAGE_SIZE, PhysPageNum};
use crate::config::LINKAGE_EKERNEL;
use crate::driver::GLOBAL_MAPPINGS;
use crate::println;
use crate::result::{Errno, SyscallResult};
use crate::sync::mutex::IrqMutex;

static USER_ALLOCATOR: IrqMutex<UserFrameAllocator> = IrqMutex::new(UserFrameAllocator::new());

pub struct UserFrameTracker {
    pub ppn: PhysPageNum,
    pub pages: usize,
}

impl Drop for UserFrameTracker {
    fn drop(&mut self) {
        USER_ALLOCATOR.lock().dealloc(&self);
    }
}

struct UserFrameAllocator(Vec<Segment>);

impl UserFrameAllocator {
    const fn new() -> Self {
        Self(Vec::new())
    }

    fn add_to_heap(&mut self, start: PhysPageNum, end: PhysPageNum) {
        self.0.push(Segment::new(start, end));
    }

    fn alloc(&mut self, pages: usize) -> SyscallResult<UserFrameTracker> {
        for segment in self.0.iter_mut() {
            if let Some(tracker) = segment.alloc(pages) {
                return Ok(tracker);
            }
        }
        warn!("[UserFrameAllocator] Out of memory for {} pages", pages);
        Err(Errno::ENOSPC)
    }

    fn dealloc(&mut self, tracker: &UserFrameTracker) {
        for segment in self.0.iter_mut() {
            if segment.start <= tracker.ppn && tracker.ppn < segment.end {
                segment.dealloc(tracker);
                return;
            }
        }
        panic!("Dealloc user frame {:?} for {} pages failed", tracker.ppn, tracker.pages);
    }
}

struct Segment {
    start: PhysPageNum,
    end: PhysPageNum,
    bitmap: BitVec,
    cur: usize,
}

impl Segment {
    fn new(start: PhysPageNum, end: PhysPageNum) -> Self {
        let bitmap = BitVec::from_elem(end.0 - start.0, false);
        Self { start, end, bitmap, cur: end.0 - start.0 }
    }

    fn alloc(&mut self, pages: usize) -> Option<UserFrameTracker> {
        let mut now = self.cur + 1;
        let mut count = 0;
        while now != self.cur {
            if now >= self.end.0 - self.start.0 {
                now = 0;
                count = 0;
            }
            if self.bitmap[now] {
                count = 0;
            } else {
                count += 1;
                if count == pages {
                    let start = now + 1 - pages;
                    for i in start..=now {
                        self.bitmap.set(i, true);
                    }
                    self.cur = now;
                    let tracker = UserFrameTracker {
                        ppn: PhysPageNum(self.start.0 + start),
                        pages,
                    };
                    return Some(tracker);
                }
            }
        }
        self.cur = self.end.0 - self.start.0;
        None
    }

    fn dealloc(&mut self, tracker: &UserFrameTracker) {
        let start = tracker.ppn.0 - self.start.0;
        for i in start..start + tracker.pages {
            self.bitmap.set(i, false);
        }
    }
}

/// 分配连续的用户页帧
///
/// SAFETY: 保证分配的页已经清零
pub fn alloc_user_frames(pages: usize) -> SyscallResult<UserFrameTracker> {
    let tracker = USER_ALLOCATOR.lock().alloc(pages)?;
    tracker.ppn.byte_array().fill(0);
    Ok(tracker)
}

pub fn free_user_memory() -> usize {
    let pages = USER_ALLOCATOR.lock().0.iter()
        .flat_map(|seg| seg.bitmap.as_bytes())
        .fold(0, |acc, byte| acc + byte.count_zeros());
    pages as usize * PAGE_SIZE
}

pub fn init() {
    let mut allocator = USER_ALLOCATOR.lock();
    for map in GLOBAL_MAPPINGS.iter() {
        if map.name.starts_with("[memory") {
            let start = max(map.phys_start, kvaddr_to_paddr(*LINKAGE_EKERNEL));
            let end = map.phys_end();
            allocator.add_to_heap(start.into(), end.into());
            println!("[kernel] Initialize user memory: {:?} - {:?}", start, end);
        }
    }
}
