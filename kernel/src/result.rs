use common::arch::{PhysPageNum, VirtPageNum};

pub type MosResult<T = ()> = Result<T, MosError>;

#[derive(Debug)]
pub enum MosError {
    OutOfMemory,
    CrossPageBoundary,
    InvalidAddress,
    PageAlreadyMapped(PhysPageNum),
    PageNotMapped(VirtPageNum),
    PageNoncopyable,
}
