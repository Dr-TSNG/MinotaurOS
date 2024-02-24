use riscv::register::sstatus;
use crate::sync::mutex::spin::SpinMutex;

mod spin;
// mod rwlock;

/// 锁策略，用于在加锁前后执行特殊操作
pub trait MutexStrategy {
    type GuardData;
    fn new_guard() -> Self::GuardData;
}

pub struct DefaultStrategy;
pub struct IrqStrategy;

pub type Mutex<T> = SpinMutex<T, DefaultStrategy>;
pub type IrqMutex<T> = SpinMutex<T, IrqStrategy>;
// TODO: Real RwLock
pub type RwLock<T> = ::spin::RwLock<T>;

impl MutexStrategy for DefaultStrategy {
    type GuardData = ();

    fn new_guard() -> Self::GuardData {}
}

pub struct IrqGuard(bool);

impl IrqGuard {
    pub fn new() -> Self {
        let sie = sstatus::read().sie();
        unsafe { sstatus::clear_sie(); }
        Self(sie)
    }
}

impl Drop for IrqGuard {
    fn drop(&mut self) {
        if self.0 {
            unsafe { sstatus::set_sie(); }
        }
    }
}

impl MutexStrategy for IrqStrategy {
    type GuardData = IrqGuard;
    fn new_guard() -> Self::GuardData {
        IrqGuard::new()
    }
}
