use alloc::sync::Arc;
use crate::process::thread::Thread;

pub struct HartContext {
    pub user_task: Option<UserTask>,
}

pub struct UserTask {
    pub thread: Arc<Thread>,
}

impl HartContext {
    pub const fn new(user_task: Option<UserTask>) -> Self {
        HartContext {
            user_task,
        }
    }
}
