use alloc::collections::VecDeque;
use async_task::{Runnable, ScheduleInfo, Task, WithInfo};
use core::future::Future;
use crate::sync::mutex::IrqMutex;

struct TaskQueue {
    queue: IrqMutex<VecDeque<Runnable>>,
}

impl TaskQueue {
    pub const fn new() -> Self {
        Self {
            queue: IrqMutex::new(VecDeque::new()),
        }
    }

    pub fn push_back(&self, runnable: Runnable) {
        self.queue.lock().push_back(runnable);
    }

    pub fn push_front(&self, runnable: Runnable) {
        self.queue.lock().push_front(runnable);
    }

    pub fn take(&self) -> Option<Runnable> {
        self.queue.lock().pop_front()
    }
}

static TASK_QUEUE: TaskQueue = TaskQueue::new();

pub fn spawn<F>(future: F) -> (Runnable, Task<F::Output>)
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
{
    let schedule = move |runnable: Runnable, info: ScheduleInfo| {
        if info.woken_while_running {
            TASK_QUEUE.push_back(runnable);
        } else {
            TASK_QUEUE.push_front(runnable);
        }
    };
    async_task::spawn(future, WithInfo(schedule))
}

/// 启动协程
pub fn start_coroutine() -> usize {
    let mut switched = 0;
    while let Some(task) = TASK_QUEUE.take() {
        task.run();
        switched += 1;
    }
    switched
}
