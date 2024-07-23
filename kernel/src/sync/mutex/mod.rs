use riscv::register::sstatus;

mod reentrant;
mod spin;
mod sync;
// mod rwlock;

/// 锁策略，用于在加锁前后执行特殊操作
pub trait MutexStrategy: 'static {
    type GuardData;
    fn new_guard() -> Self::GuardData;
}

pub struct DefaultStrategy;
pub struct IrqStrategy;

pub type Mutex<T> = spin::SpinMutex<T, DefaultStrategy>;
pub type IrqMutex<T> = spin::SpinMutex<T, IrqStrategy>;
pub type ReMutex<T> = reentrant::ReMutex<T, DefaultStrategy>;
pub type IrqReMutex<T> = reentrant::ReMutex<T, IrqStrategy>;
pub type AsyncMutex<T> = sync::AsyncMutex<T, DefaultStrategy>;

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
