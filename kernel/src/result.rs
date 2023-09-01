pub type MosResult<T = ()> = Result<T, MosError>;

#[derive(Debug)]
pub enum MosError {
    OutOfMemory,
    CrossPageBoundary,
    InvalidAddress,
    PageAlreadyMapped,
    PageNoncopyable,
}
