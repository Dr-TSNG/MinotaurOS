use alloc::sync::Arc;
use crate::mm::page_table::PageTable;
use crate::process::thread::Thread;

pub struct HartContext {
    pub user_task: Option<UserTask>,
}

pub struct UserTask {
    pub thread: Arc<Thread>,
    pub root_pt: PageTable,
}

impl HartContext {
    pub const fn new(user_task: Option<UserTask>) -> Self {
        HartContext {
            user_task,
        }
    }
}
