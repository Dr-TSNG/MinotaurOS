use alloc::sync::Arc;
use crate::mm::page_table::PageTable;
use crate::process::thread::Thread;
use crate::syscall::SyscallCode;

pub struct HartContext {
    pub user_task: Option<UserTask>,
    pub last_syscall: SyscallCode,
    pub timer_during_sys: usize,
}

pub struct UserTask {
    pub thread: Arc<Thread>,
    pub token: usize,
    pub root_pt: PageTable,
}

impl HartContext {
    pub const fn kernel() -> Self {
        HartContext {
            user_task: None,
            last_syscall: SyscallCode::Shutdown,
            timer_during_sys: 0,
        }
    }

    pub fn user(thread: Arc<Thread>) -> Self {
        let proc_inner = thread.process.inner.lock();
        let user_task = UserTask {
            thread: thread.clone(),
            token: proc_inner.addr_space.token,
            root_pt: proc_inner.addr_space.root_pt,
        };
        HartContext {
            user_task: Some(user_task),
            last_syscall: SyscallCode::Shutdown,
            timer_during_sys: 0,
        }
    }
}
