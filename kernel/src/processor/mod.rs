use alloc::sync::Arc;
use core::sync::atomic::AtomicBool;
use crate::process::Process;
use crate::process::thread::Thread;
use crate::processor::hart::local_hart;
use crate::trap::context::TrapContext;

pub mod context;
pub mod hart;

pub static SYSTEM_SHUTDOWN: AtomicBool = AtomicBool::new(false);

pub fn current_thread() -> &'static Arc<Thread> {
    local_hart().current_thread().unwrap()
}

pub fn current_process() -> &'static Arc<Process> {
    &current_thread().process
}

pub fn current_trap_ctx() -> &'static mut TrapContext {
    &mut current_thread().inner().trap_ctx
}
