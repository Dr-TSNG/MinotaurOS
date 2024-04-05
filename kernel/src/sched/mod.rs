pub mod time;
pub mod executor;

use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use log::debug;
use pin_project::pin_project;
use crate::process::thread::Thread;
use crate::processor::context::{HartContext, UserTask};
use crate::processor::current_thread;
use crate::processor::hart::local_hart;
use crate::trap::user::{trap_from_user, trap_return};

#[pin_project]
struct HartTaskFuture<F: Future<Output=()> + Send + 'static> {
    ctx: HartContext,
    #[pin]
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
            root_pt: thread.process.inner.lock().addr_space.root_pt,
        };
        let ctx = HartContext::new(Some(task));
        Self { ctx, fut }
    }
}

impl<F: Future<Output=()> + Send + 'static> Future for HartTaskFuture<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let hart = local_hart();
        hart.switch_ctx(&mut this.ctx);
        let ret = this.fut.poll(cx);
        hart.switch_ctx(&mut this.ctx);
        ret
    }
}

struct YieldFuture(bool);

impl Future for YieldFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        if self.0 {
            return Poll::Ready(());
        }
        self.0 = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

async fn thread_loop(thread: Arc<Thread>) {
    loop {
        trap_return();
        trap_from_user().await;
        if let Some(code) = thread.inner().exit_code {
            debug!("Thread {} terminated with code {}", current_thread().tid.0, code);
            break;
        }
    }
    thread.on_terminate();
}

pub async fn yield_now() {
    YieldFuture(false).await;
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
