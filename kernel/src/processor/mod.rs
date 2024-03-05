use alloc::sync::Arc;
use crate::process::thread::Thread;
use crate::processor::hart::local_hart;

pub mod context;
pub mod hart;

pub fn current_thread() -> &'static Arc<Thread> {
    local_hart().current_thread().unwrap()
}
