use crate::mm::allocator::IdAllocator;
use crate::process::Tid;
use crate::sync::mutex::IrqMutex;

static TID_ALLOCATOR: IrqMutex<IdAllocator> = IrqMutex::new(IdAllocator::new());

#[derive(Eq, PartialEq)]
pub struct TidTracker(pub Tid);

impl TidTracker {
    pub fn new() -> Self {
        Self(TID_ALLOCATOR.lock().alloc())
    }
}

impl Drop for TidTracker {
    fn drop(&mut self) {
        TID_ALLOCATOR.lock().dealloc(self.0)
    }
}
