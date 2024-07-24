use alloc::sync::{Arc, Weak};
use crate::mm::asid::ASID;
use crate::mm::page_table::PageTable;
use crate::process::thread::Thread;

pub struct HartContext {
    pub user_task: Option<UserTask>,
}

pub struct UserTask {
    pub thread: Arc<Thread>,
    pub root_pt: PageTable,
    pub asid: Weak<ASID>,
}

impl HartContext {
    pub const fn kernel() -> Self {
        HartContext {
            user_task: None,
        }
    }

    pub fn user(thread: Arc<Thread>) -> Self {
        let proc_inner = thread.process.inner.lock();
        let user_task = UserTask {
            thread: thread.clone(),
            root_pt: proc_inner.addr_space.root_pt,
            asid: proc_inner.addr_space.asid.clone(),
        };
        HartContext {
            user_task: Some(user_task),
        }
    }
}
