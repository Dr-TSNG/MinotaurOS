mod heap;
mod id;
mod user;

pub use heap::{alloc_kernel_frames, HeapFrameTracker, init as init_heap};
pub use user::{alloc_user_frames, free_user_memory, UserFrameTracker, init as init_user};
pub use id::IdAllocator;
