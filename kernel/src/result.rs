use common::arch::{PhysPageNum, VirtAddr};

pub type MosResult<T = ()> = Result<T, MosError>;

#[derive(Debug)]
pub enum MosError {
    OutOfMemory,
    CrossPageBoundary,
    BadAddress(VirtAddr),
    PageAlreadyMapped(PhysPageNum),
    PageNotMapped(PhysPageNum),
    PageNoncopyable,
}
