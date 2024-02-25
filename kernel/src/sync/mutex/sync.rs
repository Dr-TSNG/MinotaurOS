use core::cell::UnsafeCell;
use core::future::Future;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};
use futures_core::task::__internal::AtomicWaker;
use crate::sync::mutex::MutexStrategy;

pub struct AsyncMutex<T: ?Sized, S: MutexStrategy> {
    _marker: PhantomData<S>,
    lock: AtomicBool,
    waker: AtomicWaker,
    data: UnsafeCell<T>,
}

pub struct AsyncMutexGuard<'a, T: ?Sized, S: MutexStrategy> {
    mutex: &'a AsyncMutex<T, S>,
    guard: S::GuardData,
}

impl<T, S: MutexStrategy> AsyncMutex<T, S> {
    pub const fn new(data: T) -> Self {
        AsyncMutex {
            _marker: PhantomData,
            lock: AtomicBool::new(false),
            data: UnsafeCell::new(data),
            waker: AtomicWaker::new(),
        }
    }

    #[inline(always)]
    pub fn is_locked(&self) -> bool {
        self.lock.load(Ordering::Relaxed)
    }

    #[inline(always)]
    pub async fn lock(&self) -> AsyncMutexGuard<T, S> {
        let guard = S::new_guard();
        let mut fut = self.lock_fut();
        while self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err() {
            fut.await;
            fut = self.lock_fut();
        }
        AsyncMutexGuard {
            mutex: self,
            guard,
        }
    }

    fn lock_fut(&self) -> impl Future<Output = ()> {
        let waker = self.waker.clone();
        async move {
            waker.await;
        }
    }
}

impl<'a, T: ?Sized, S: MutexStrategy> Deref for AsyncMutexGuard<'a, T, S> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &T {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<'a, T: ?Sized, S: MutexStrategy> DerefMut for AsyncMutexGuard<'a, T, S> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<'a, T: ?Sized, S: MutexStrategy> Drop for AsyncMutexGuard<'a, T, S> {
    #[inline(always)]
    fn drop(&mut self) {
        self.mutex.lock.store(false, Ordering::Release);
        self.mutex.waker.wake();
    }
}
