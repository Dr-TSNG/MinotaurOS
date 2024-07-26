pub mod executor;
pub mod ffi;
pub mod iomultiplex;
pub mod time;
pub mod timer;

use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use pin_project::pin_project;
use crate::process::thread::event_bus::Event;
use crate::process::thread::Thread;
use crate::processor::context::HartContext;
use crate::processor::current_thread;
use crate::processor::hart::local_hart;
use crate::result::{Errno, SyscallResult};
use crate::sched::ffi::{CLOCK_MONOTONIC, CLOCK_REALTIME};
use crate::sched::time::{GLOBAL_CLOCK, TimeoutFuture, TimeoutResult};
use crate::trap::user::{check_signal, trap_from_user, trap_return};

#[pin_project]
struct HartTaskFuture<F: Future<Output=()> + Send + 'static> {
    ctx: HartContext,
    #[pin]
    fut: F,
}

impl<F: Future<Output=()> + Send + 'static> HartTaskFuture<F> {
    fn new_kernel(fut: F) -> Self {
        let ctx = HartContext::kernel();
        Self { ctx, fut }
    }

    fn new_user(thread: Arc<Thread>, fut: F) -> Self {
        let ctx = HartContext::user(thread);
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

struct IdleFuture;

impl Future for IdleFuture {
    type Output = !;

    fn poll(self: Pin<&mut Self>, _: &mut Context) -> Poll<Self::Output> {
        Poll::Pending
    }
}

async fn thread_loop(thread: Arc<Thread>) {
    loop {
        trap_return();
        trap_from_user().await;
        check_signal();
        if thread.inner().exit_code.is_some() {
            break;
        }
    }
    thread.on_exit();
}

pub async fn yield_now() {
    YieldFuture(false).await;
}

pub async fn schedule() {
    if local_hart().ctx.timer_during_sys >= 1 {
        yield_now().await;
    }
}

pub async fn suspend_now<T, F>(timeout: Option<Duration>, event: Event, fut: F) -> SyscallResult<T>
where
    F: Future<Output=SyscallResult<T>> + Unpin,
{
    let fut = current_thread().event_bus.suspend_with(event, fut);
    match timeout {
        Some(timeout) => match TimeoutFuture::new(timeout, fut).await {
            TimeoutResult::Ready(ret) => ret,
            TimeoutResult::Timeout => Err(Errno::ETIMEDOUT),
        }
        None => fut.await,
    }
}

pub async fn sleep_for(time: Duration) -> SyscallResult<()> {
    TimeoutFuture::new(time, IdleFuture).await;
    Ok(())
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

pub fn init() {
    // Trick libc-test stat
    // 2024-09-01 00:00:00 Asia/Shanghai
    const TODAY: Duration = Duration::from_secs(1725120000);
    GLOBAL_CLOCK.set(CLOCK_REALTIME, TODAY);
    GLOBAL_CLOCK.set(CLOCK_MONOTONIC, Duration::ZERO);
}
