use alloc::collections::VecDeque;
use async_task::{Runnable, ScheduleInfo, Task, WithInfo};
use core::future::Future;
use crate::driver::BOARD_INFO;
use crate::process::monitor::PROCESS_MONITOR;
use crate::processor::hart::local_hart;
use crate::sched::timer::query_timer;
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

/// 开始执行任务
pub fn run_executor() {
    loop {
        while let Some(task) = TASK_QUEUE.take() {
            task.run();
        }
        query_timer();
        BOARD_INFO.plic.handle_irq(local_hart().id);
        core::hint::spin_loop();
        if PROCESS_MONITOR.lock().init_proc().strong_count() == 0 {
            break;
        }
    }
}
