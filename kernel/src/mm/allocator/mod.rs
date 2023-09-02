use buddy_system_allocator::Heap;
use spin::Mutex;

mod heap;
mod user;

pub use heap::{alloc_kernel_frames, HeapFrameTracker};
pub use user::{alloc_user_frames, alloc_user_frames_cont, UserFrameTracker};

struct Allocator(Mutex<Heap<32>>);

impl Allocator {
    const fn empty() -> Self {
        Allocator(Mutex::new(Heap::empty()))
    }
}

pub fn init() {
    heap::init();
    user::init();
}
