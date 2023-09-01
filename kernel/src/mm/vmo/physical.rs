use common::arch::PhysPageNum;

pub struct VMObjectPhysical {
    start: PhysPageNum,
    pages: usize,
}
