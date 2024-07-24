use alloc::sync::Arc;
use crate::mm::page_table::PageTable;
use crate::process::thread::Thread;
use crate::result::SyscallResult;

pub struct HartContext {
    pub user_task: Option<UserTask>,
    pub page_test: bool,
    pub last_kernel_trap: SyscallResult,
}

pub struct UserTask {
    pub thread: Arc<Thread>,
    pub root_pt: PageTable,
}

impl HartContext {
    pub const fn new(user_task: Option<UserTask>) -> Self {
        HartContext {
            user_task,
            page_test: false,
            last_kernel_trap: Ok(()),
        }
    }
}
