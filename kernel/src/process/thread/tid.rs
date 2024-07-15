use crate::mm::allocator::IdAllocator;
use crate::process::monitor::MONITORS;
use crate::process::Tid;
use crate::sync::mutex::IrqMutex;

static TID_ALLOCATOR: IrqMutex<IdAllocator> = IrqMutex::new(IdAllocator::new(1));

#[derive(Eq, PartialEq)]
pub struct TidTracker(pub Tid);

impl TidTracker {
    pub fn new() -> Self {
        Self(TID_ALLOCATOR.lock().alloc())
    }
}

impl Drop for TidTracker {
    fn drop(&mut self) {
        let mut monitors = MONITORS.lock();
        monitors.thread.remove(self.0);
        monitors.process.remove(self.0);
        monitors.group.remove_group(self.0);
        TID_ALLOCATOR.lock().dealloc(self.0)
    }
}
