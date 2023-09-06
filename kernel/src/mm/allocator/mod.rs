mod heap;
mod user;

pub use heap::{alloc_kernel_frames, HeapFrameTracker};
pub use user::{alloc_user_frames, UserFrameTracker};

pub fn init() {
    heap::init();
    user::init();
}
