use common::arch::PhysPageNum;

pub struct UserFrameTracker {
    pub ppn: PhysPageNum,
    pub pages: usize,
}
