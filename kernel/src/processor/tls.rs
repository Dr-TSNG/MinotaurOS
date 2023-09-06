use alloc::sync::Arc;
use core::cell::{RefCell, RefMut, UnsafeCell};
use core::ops::Deref;
use crate::config::MAX_HARTS;
use super::hart::current_hart;

/// 线程局部存储，只有所有硬件线程的引用被 drop 后才会全部清空
pub struct ThreadLocal<T> {
    inner: UnsafeCell<[RefCell<Option<T>>; MAX_HARTS]>,
}

// Safety: ThreadLocal is Sync because it is only accessed by the current hart.
unsafe impl<T> Sync for ThreadLocal<T> {}

impl<T> ThreadLocal<T> {
    pub const fn new() -> Self {
        Self {
            inner: UnsafeCell::new([const { RefCell::new(None) }; MAX_HARTS]),
        }
    }

    pub fn get(&self) -> RefMut<Option<T>> {
        let hart_id = current_hart().id;
        unsafe {
            (*self.inner.get())[hart_id].borrow_mut()
        }
    }

    pub fn set(&self, value: T) {
        let hart_id = current_hart().id;
        unsafe {
            (*self.inner.get())[hart_id].replace(Some(value));
        }
    }

    pub fn clear(&self) {
        let hart_id = current_hart().id;
        unsafe {
            (*self.inner.get())[hart_id].replace(None);
        }
    }
}

/// 线程局部存储的包装器，被 drop 后会清空当前线程的局部存储，可以和 `Rc` 配合使用
pub struct ThreadLocalHolder<T>(Arc<ThreadLocal<T>>);

impl<T> Deref for ThreadLocalHolder<T> {
    type Target = ThreadLocal<T>;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl<T> Drop for ThreadLocalHolder<T> {
    fn drop(&mut self) {
        self.0.clear();
    }
}

impl<T> ThreadLocalHolder<T> {
    /// 创建一个线程局部存储的包装器
    pub fn new(value: ThreadLocal<T>) -> Self {
        Self(Arc::new(value))
    }

    /// 从线程局部存储的引用创建一个包装器，通常用于接收其他线程发送的引用，需要避免在同一个线程中创建多个包装器
    pub fn from(value: Arc<ThreadLocal<T>>) -> Self {
        Self(value)
    }

    /// 获取线程局部存储的引用，仅用于发送给其他线程
    pub fn share(&self) -> Arc<ThreadLocal<T>> {
        self.0.clone()
    }
}
