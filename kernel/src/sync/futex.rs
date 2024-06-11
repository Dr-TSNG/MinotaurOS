use crate::arch::VirtAddr;
use crate::process::Tid;
use crate::processor::{current_process, current_thread};
use crate::result::SyscallResult;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::cell::SyncUnsafeCell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU32, Ordering};
use core::task::{Context, Poll, Waker};
use log::info;

#[derive(Default)]
pub struct FutexQueue(BTreeMap<VirtAddr, BTreeMap<Tid, FutexWaker>>);

impl FutexQueue {
    pub fn wake(&mut self, addr: VirtAddr, nval: usize) -> usize {
        let mut woken = 0;
        if let Some(queue) = self.0.get_mut(&addr) {
            for _ in 0..nval {
                if let Some((tid, waker)) = queue.pop_first() {
                    info!("[futex] Wake up {} at {:?}", tid, addr);
                    waker.wake();
                    woken += 1;
                } else {
                    break;
                }
            }
        }
        woken
    }

    pub fn requeue(
        &mut self,
        old_addr: VirtAddr,
        new_addr: VirtAddr,
        nval_wake: usize,
        nval_req: usize,
    ) -> usize {
        if old_addr == new_addr {
            return 0;
        }
        let mut woken_req = self.wake(old_addr, nval_wake);
        for _ in 0..nval_req {
            if let Some(queue) = self.0.get_mut(&old_addr) {
                if let Some((tid, waker)) = queue.pop_first() {
                    info!(
                        "[futex] Requeue {} from {:?} to {:?}",
                        tid, old_addr, new_addr
                    );
                    unsafe {
                        *(waker.addr.get()) = new_addr;
                    }
                    self.register(tid, waker);
                    woken_req += 1;
                } else {
                    break;
                }
            }
        }
        woken_req
    }

    fn register(&mut self, tid: Tid, waker: FutexWaker) {
        let addr = unsafe { *waker.addr.get() };
        if let Some(queue) = self.0.get_mut(&addr) {
            queue.insert(tid, waker);
        } else {
            let mut queue = BTreeMap::new();
            queue.insert(tid, waker);
            self.0.insert(addr, queue);
        }
    }

    fn unregister(&mut self, addr: VirtAddr, tid: Tid) {
        if let Some(queue) = self.0.get_mut(&addr) {
            queue.remove(&tid);
        }
    }
}

struct FutexWaker {
    addr: Arc<SyncUnsafeCell<VirtAddr>>,
    waker: Waker,
}

impl FutexWaker {
    fn new(addr: VirtAddr, waker: Waker) -> Self {
        Self {
            addr: Arc::new(SyncUnsafeCell::new(addr)),
            waker,
        }
    }

    fn wake(self) {
        self.waker.wake();
    }
}

pub struct FutexFuture {
    addr: Arc<SyncUnsafeCell<VirtAddr>>,
    emplaced: SyncUnsafeCell<bool>,
    val: u32,
}

impl FutexFuture {
    pub fn new(addr: VirtAddr, val: u32) -> Self {
        Self {
            addr: Arc::new(SyncUnsafeCell::new(addr)),
            emplaced: SyncUnsafeCell::new(false),
            val,
        }
    }
}

impl Future for FutexFuture {
    type Output = SyscallResult<()>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut proc_inner = current_process().inner.lock();
        let addr = unsafe { *this.addr.get() };
        let emplaced = this.emplaced.get_mut();
        if *emplaced {
            info!("[futex] Woken up at {:?}", addr);
            proc_inner
                .futex_queue
                .unregister(addr, current_thread().tid.0);
            Poll::Ready(Ok(()))
        } else {
            let waker = FutexWaker::new(addr, cx.waker().clone());
            proc_inner
                .futex_queue
                .register(current_thread().tid.0, waker);
            *emplaced = true;
            let val =
                unsafe { AtomicU32::from_ptr(addr.as_ptr().cast::<u32>()).load(Ordering::Relaxed) };
            info!(
                "[futex] Wait at {:?} for val {:#x}, expected {:#x}",
                addr, val, this.val
            );
            if val != this.val {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
    }
}
