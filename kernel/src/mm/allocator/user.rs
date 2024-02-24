use alloc::vec::Vec;
use bitvec_rs::BitVec;
use log::trace;
use crate::arch::PhysPageNum;
use crate::board::PHYS_MEMORY;
use crate::println;
use crate::result::{MosError, MosResult};
use crate::sync::mutex::IrqMutex;

static USER_ALLOCATOR: IrqMutex<UserFrameAllocator> = IrqMutex::new(UserFrameAllocator::new());

pub struct UserFrameTracker {
    pub ppn: PhysPageNum,
    pub pages: usize,
}

impl Drop for UserFrameTracker {
    fn drop(&mut self) {
        trace!("UserFrameAllocator: dealloc user frame {:?} for {} pages", self.ppn, self.pages);
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

    fn alloc(&mut self, pages: usize) -> MosResult<UserFrameTracker> {
        for segment in self.0.iter_mut() {
            if let Some(tracker) = segment.alloc(pages) {
                return Ok(tracker);
            }
        }
        Err(MosError::OutOfMemory)
    }

    fn dealloc(&mut self, tracker: &UserFrameTracker) {
        for segment in self.0.iter_mut() {
            if segment.start <= tracker.ppn && tracker.ppn < segment.end {
                segment.dealloc(tracker);
                return;
            }
        }
        panic!("dealloc user frame {:?} for {} pages failed", tracker.ppn, tracker.pages);
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
                    let start = now - pages + 1;
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
pub fn alloc_user_frames(pages: usize) -> MosResult<UserFrameTracker> {
    USER_ALLOCATOR.lock().alloc(pages)
}

pub fn init() {
    let mut allocator = USER_ALLOCATOR.lock();
    PHYS_MEMORY.iter().for_each(|&(start, end)| {
        println!("[kernel] Initialize user memory: {:?} - {:?}", start, end);
        allocator.add_to_heap(start.into(), end.into());
    });
}
