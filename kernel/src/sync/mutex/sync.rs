use core::cell::UnsafeCell;
use core::future::poll_fn;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};
use futures::task::AtomicWaker;
use crate::sync::mutex::MutexStrategy;

pub struct AsyncMutex<T: ?Sized, S: MutexStrategy> {
    _marker: PhantomData<S>,
    lock: AtomicBool,
    waker: AtomicWaker,
    data: UnsafeCell<T>,
}

pub struct AsyncMutexGuard<'a, T: ?Sized, S: MutexStrategy> {
    mutex: &'a AsyncMutex<T, S>,
    _guard: S::GuardData,
}

unsafe impl<T: ?Sized + Send, S: MutexStrategy> Sync for AsyncMutex<T, S> {}

unsafe impl<T: ?Sized + Send, S: MutexStrategy> Send for AsyncMutex<T, S> {}

unsafe impl<'a, T: ?Sized + Send, S: MutexStrategy> Sync for AsyncMutexGuard<'a, T, S> {}

unsafe impl<'a, T: ?Sized + Send, S: MutexStrategy> Send for AsyncMutexGuard<'a, T, S> {}

impl<T, S: MutexStrategy> AsyncMutex<T, S> {
    pub const fn new(data: T) -> Self {
        AsyncMutex {
            _marker: PhantomData,
            lock: AtomicBool::new(false),
            waker: AtomicWaker::new(),
            data: UnsafeCell::new(data),
        }
    }

    pub fn is_locked(&self) -> bool {
        self.lock.load(Ordering::Relaxed)
    }

    pub async fn lock(&self) -> AsyncMutexGuard<T, S> {
        poll_fn(|cx| self.poll_lock(cx)).await
    }

    fn poll_lock(&self, cx: &Context<'_>) -> Poll<AsyncMutexGuard<T, S>> {
        let guard = S::new_guard();
        if self.lock.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            return Poll::Ready(AsyncMutexGuard {
                mutex: self,
                _guard: guard,
            });
        }

        self.waker.register(cx.waker());

        if self.lock.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            return Poll::Ready(AsyncMutexGuard {
                mutex: self,
                _guard: guard,
            });
        }

        Poll::Pending
    }
}


impl<T: ?Sized + Default, S: MutexStrategy> Default for AsyncMutex<T, S> {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl<'a, T: ?Sized, S: MutexStrategy> Deref for AsyncMutexGuard<'a, T, S> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<'a, T: ?Sized, S: MutexStrategy> DerefMut for AsyncMutexGuard<'a, T, S> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<'a, T: ?Sized, S: MutexStrategy> Drop for AsyncMutexGuard<'a, T, S> {
    fn drop(&mut self) {
        self.mutex.lock.store(false, Ordering::Release);
        self.mutex.waker.wake();
    }
}
