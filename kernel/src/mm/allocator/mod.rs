mod heap;
mod id;
mod user;

pub use heap::{alloc_kernel_frames, HeapFrameTracker};
pub use user::{alloc_user_frames, UserFrameTracker};
pub use id::IdAllocator;

pub fn init() {
    heap::init();
    user::init();
}
