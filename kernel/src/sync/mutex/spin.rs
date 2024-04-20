use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use crate::sched::time::current_time;
use crate::sync::mutex::MutexStrategy;

pub struct SpinMutex<T: ?Sized, S: MutexStrategy> {
    _marker: PhantomData<S>,
    lock: AtomicBool,
    data: UnsafeCell<T>,
}

pub struct SpinMutexGuard<'a, T: ?Sized, S: MutexStrategy> {
    mutex: &'a SpinMutex<T, S>,
    guard: S::GuardData,
}

unsafe impl<T: ?Sized + Send, S: MutexStrategy> Sync for SpinMutex<T, S> {}

unsafe impl<T: ?Sized + Send, S: MutexStrategy> Send for SpinMutex<T, S> {}

impl<T, S: MutexStrategy> SpinMutex<T, S> {
    pub const fn new(data: T) -> Self {
        SpinMutex {
            _marker: PhantomData,
            lock: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    pub fn is_locked(&self) -> bool {
        self.lock.load(Ordering::Relaxed)
    }

    pub fn try_lock(&self) -> Option<SpinMutexGuard<T, S>> {
        if self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok() {
            Some(SpinMutexGuard {
                mutex: self,
                guard: S::new_guard(),
            })
        } else {
            None
        }
    }
    
    pub fn lock(&self) -> SpinMutexGuard<T, S> {
        let start_time = current_time();
        loop {
            if let Some(guard) = self.try_lock() {
                return guard;
            }
            core::hint::spin_loop();
            if current_time() - start_time > Duration::from_secs(5) {
                panic!("SpinMutex deadlock");
            }
        }
    }
}

impl<T: ?Sized + Default, S: MutexStrategy> Default for SpinMutex<T, S> {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl<'a, T: ?Sized, S: MutexStrategy> SpinMutexGuard<'a, T, S> {
    pub fn apply<F: FnOnce(&T) -> R, R>(self, f: F) -> R {
        f(self.deref())
    }

    pub fn apply_mut<F: FnOnce(&mut T) -> R, R>(mut self, f: F) -> R {
        f(self.deref_mut())
    }
}

impl<'a, T: ?Sized, S: MutexStrategy> Deref for SpinMutexGuard<'a, T, S> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<'a, T: ?Sized, S: MutexStrategy> DerefMut for SpinMutexGuard<'a, T, S> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<'a, T: ?Sized, S: MutexStrategy> Drop for SpinMutexGuard<'a, T, S> {
    fn drop(&mut self) {
        self.mutex.lock.store(false, Ordering::Release);
    }
}
