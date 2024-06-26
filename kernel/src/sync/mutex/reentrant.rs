use core::cell::{Cell, UnsafeCell};
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;

use crate::processor::hart::local_hart;
use crate::sched::time::current_time;
use crate::sync::mutex::MutexStrategy;

pub struct ReMutex<T: ?Sized, S: MutexStrategy> {
    _marker: PhantomData<S>,
    lock: Cell<usize>,
    owner: AtomicUsize,
    data: UnsafeCell<T>,
}

pub struct ReMutexGuard<'a, T: ?Sized, S: MutexStrategy> {
    mutex: &'a ReMutex<T, S>,
    guard: S::GuardData,
}

unsafe impl<T: ?Sized + Send, S: MutexStrategy> Sync for ReMutex<T, S> {}

unsafe impl<T: ?Sized + Send, S: MutexStrategy> Send for ReMutex<T, S> {}

const NOBODY: usize = 0xdeadbeef;

impl<T, S: MutexStrategy> ReMutex<T, S> {
    pub const fn new(data: T) -> Self {
        ReMutex {
            _marker: PhantomData,
            lock: Cell::new(0),
            owner: AtomicUsize::new(NOBODY),
            data: UnsafeCell::new(data),
        }
    }

    pub fn is_locked(&self) -> Option<usize> {
        let owner = self.owner.load(Ordering::Relaxed);
        (owner != NOBODY).then(|| owner)
    }

    pub fn try_lock(&self) -> Option<ReMutexGuard<T, S>> {
        if self.owner.load(Ordering::Relaxed) == local_hart().id {
            self.lock.set(self.lock.get() + 1);
        } else if self
            .owner
            .compare_exchange(NOBODY, local_hart().id, Ordering::Acquire, Ordering::Relaxed)
            .is_ok() {
            self.lock.set(1);
        } else {
            return None;
        }
        Some(ReMutexGuard {
            mutex: self,
            guard: S::new_guard(),
        })
    }

    pub fn lock(&self) -> ReMutexGuard<T, S> {
        let start_time = current_time();
        loop {
            if let Some(guard) = self.try_lock() {
                return guard;
            }
            core::hint::spin_loop();
            if current_time() - start_time > Duration::from_secs(5) {
                panic!("ReMutex deadlock");
            }
        }
    }
}

impl<T: ?Sized + Default, S: MutexStrategy> Default for ReMutex<T, S> {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl<T: ?Sized, S: MutexStrategy> ReMutexGuard<'_, T, S> {
    pub fn apply<F: FnOnce(&T) -> R, R>(self, f: F) -> R {
        f(self.deref())
    }

    pub fn apply_mut<F: FnOnce(&mut T) -> R, R>(mut self, f: F) -> R {
        f(self.deref_mut())
    }
}

impl<T: ?Sized, S: MutexStrategy> Deref for ReMutexGuard<'_, T, S> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T: ?Sized, S: MutexStrategy> DerefMut for ReMutexGuard<'_, T, S> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<T: ?Sized, S: MutexStrategy> Drop for ReMutexGuard<'_, T, S> {
    fn drop(&mut self) {
        let lock_before = self.mutex.lock.get();
        self.mutex.lock.set(lock_before - 1);
        if lock_before == 1 {
            self.mutex.owner.store(NOBODY, Ordering::Relaxed);
        }
    }
}
