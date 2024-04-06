use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::task::Wake;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use log::trace;

pub mod mutex;
pub mod once;

struct BlockWaker;

impl Wake for BlockWaker {
    fn wake(self: Arc<Self>) {
        trace!("Block waker wakes");
    }
}

struct TakeWakerFuture;

impl Future for TakeWakerFuture {
    type Output = Waker;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(cx.waker().clone())
    }
}

/// 阻塞当前线程直到 future 执行完成
///
/// future 不会被调度，而是一直被轮询直到返回 Ready
pub fn block_on<T>(fut: impl Future<Output=T>) -> T {
    let mut fut = Box::pin(fut);

    let waker = Arc::new(BlockWaker).into();
    let mut ctx = Context::from_waker(&waker);

    loop {
        match fut.as_mut().poll(&mut ctx) {
            Poll::Ready(res) => return res,
            Poll::Pending => continue,
        }
    }
}

/// 获取当前 async 上下文的 waker
pub async fn take_waker() -> Waker {
    TakeWakerFuture.await
}
