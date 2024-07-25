use async_task::{Runnable, ScheduleInfo, Task, WithInfo};
use core::future::Future;
use core::sync::atomic::Ordering;
use crossbeam_queue::SegQueue;
use crate::processor::SYSTEM_SHUTDOWN;

struct TaskQueue {
    fifo: SegQueue<Runnable>,
    prio: SegQueue<Runnable>,
}

impl TaskQueue {
    const fn new() -> Self {
        Self {
            fifo: SegQueue::new(),
            prio: SegQueue::new(),
        }
    }

    fn push_fifo(&self, runnable: Runnable) {
        self.fifo.push(runnable);
    }

    fn push_prio(&self, runnable: Runnable) {
        self.prio.push(runnable);
    }

    fn take(&self) -> Option<Runnable> {
        self.prio.pop().or_else(|| self.fifo.pop())
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
            TASK_QUEUE.push_fifo(runnable);
        } else {
            TASK_QUEUE.push_prio(runnable);
        }
    };
    async_task::spawn(future, WithInfo(schedule))
}

/// 开始执行任务
pub fn run_executor() {
    while !SYSTEM_SHUTDOWN.load(Ordering::Relaxed) {
        if let Some(task) = TASK_QUEUE.take() {
            task.run();
        } else {
            core::hint::spin_loop();
        }
    }
}
