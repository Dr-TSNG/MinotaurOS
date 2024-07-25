use alloc::collections::VecDeque;
use core::cell::Cell;
use async_task::{Builder, ScheduleInfo, Task, WithInfo};
use core::future::Future;
use log::warn;
use crate::config::MAX_HARTS;
use crate::driver::BOARD_INFO;
use crate::process::monitor::MONITORS;
use crate::processor::hart::local_hart;
use crate::sync::mutex::IrqMutex;

type Runnable = async_task::Runnable<TaskMeta>;

struct TaskQueue {
    global_queue: IrqMutex<VecDeque<Runnable>>,
    hart_queues: [IrqMutex<VecDeque<Runnable>>; MAX_HARTS],
}

#[derive(Default)]
pub struct TaskMeta {
    last_hart: Cell<Option<usize>>,
}

unsafe impl Sync for TaskMeta {}

impl TaskQueue {
    pub const fn new() -> Self {
        const fn new_mutex() -> IrqMutex<VecDeque<Runnable>> {
            IrqMutex::new(VecDeque::new())
        }
        Self {
            global_queue: new_mutex(),
            hart_queues: [const { new_mutex() }; MAX_HARTS],
        }
    }

    pub fn push_back(&self, runnable: Runnable) {
        match runnable.metadata().last_hart.get() {
            Some(hart) => self.hart_queues[hart].lock().push_back(runnable),
            None => self.global_queue.lock().push_back(runnable),
        }
    }

    pub fn push_front(&self, runnable: Runnable) {
        match runnable.metadata().last_hart.get() {
            Some(hart) => self.hart_queues[hart].lock().push_front(runnable),
            None => self.global_queue.lock().push_front(runnable),
        }
    }

    pub fn take(&self) -> Option<Runnable> {
        fn take_from(queue: &mut VecDeque<Runnable>) -> Option<Runnable> {
            queue.pop_front()
        }
        take_from(&mut self.hart_queues[local_hart().id].lock())
            .or_else(|| take_from(&mut self.global_queue.lock()))
            .or_else(|| {
                for i in 0..BOARD_INFO.smp {
                    if i != local_hart().id {
                        if let Some(task) = take_from(&mut self.hart_queues[i].lock()) {
                            warn!("[executor] Steal task from hart {}", i);
                            return Some(task);
                        }
                    }
                }
                None
            })
    }
}

static TASK_QUEUE: TaskQueue = TaskQueue::new();

pub fn spawn<F>(future: F) -> (Runnable, Task<F::Output, TaskMeta>)
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
    Builder::new()
        .metadata(Default::default())
        .spawn(|_| future, WithInfo(schedule))
}

/// 开始执行任务
pub fn run_executor() {
    loop {
        if let Some(task) = TASK_QUEUE.take() {
            task.metadata().last_hart.set(Some(local_hart().id));
            task.run();
        } else {
            core::hint::spin_loop();
        }
        if MONITORS.lock().process.init_proc().strong_count() == 0 {
            break;
        }
    }
}
