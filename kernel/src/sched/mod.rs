pub mod time;

use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use log::debug;
use crate::process::thread::Thread;
use crate::processor::context::{HartContext, UserTask};
use crate::processor::current_thread;
use crate::processor::hart::local_hart;
use crate::sync::{executor, take_waker};
use crate::trap::user::{trap_from_user, trap_return};

struct HartTaskFuture<F: Future<Output=()> + Send + 'static> {
    ctx: HartContext,
    fut: F,
}

impl<F: Future<Output=()> + Send + 'static> HartTaskFuture<F> {
    fn new_kernel(fut: F) -> Self {
        let ctx = HartContext::new(None);
        Self { ctx, fut }
    }

    fn new_user(thread: Arc<Thread>, fut: F) -> Self {
        let task = UserTask {
            thread: thread.clone(),
        };
        let ctx = HartContext::new(Some(task));
        Self { ctx, fut }
    }
}

impl<F: Future<Output=()> + Send + 'static> Future for HartTaskFuture<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: HartContext 中不含有指针，所以可以被 swap
        let this = unsafe { self.get_unchecked_mut() };
        let hart = local_hart();
        hart.switch_ctx(&mut this.ctx);
        let ret = unsafe { Pin::new_unchecked(&mut this.fut).poll(cx) };
        hart.switch_ctx(&mut this.ctx);
        ret
    }
}

async fn thread_loop(thread: Arc<Thread>) {
    thread.inner().waker = Some(take_waker().await);
    loop {
        trap_return();
        trap_from_user().await;
        if thread.inner().terminated {
            debug!("Thread {} terminated", current_thread().tid.0);
            break;
        }
    }
    thread.on_terminate();
}

pub fn spawn_kernel_thread<F: Future<Output=()> + Send + 'static>(kernel_thread: F) {
    let future = HartTaskFuture::new_kernel(kernel_thread);
    let (runnable, task) = executor::spawn(future);
    runnable.schedule();
    task.detach();
}

pub fn spawn_user_thread(thread: Arc<Thread>) {
    let future = HartTaskFuture::new_user(thread.clone(), thread_loop(thread));
    let (runnable, task) = executor::spawn(future);
    runnable.schedule();
    task.detach();
}
