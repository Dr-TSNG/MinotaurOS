use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::task::Wake;
use core::future::Future;
use core::task::{Context, Poll};

pub mod ffi;
pub mod futex;
pub mod mutex;
pub mod once;

struct BlockWaker;

impl Wake for BlockWaker {
    fn wake(self: Arc<Self>) {}
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
