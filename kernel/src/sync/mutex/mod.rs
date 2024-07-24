use crate::processor::hart::KIntrGuard;

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

impl MutexStrategy for IrqStrategy {
    type GuardData = KIntrGuard;
    fn new_guard() -> Self::GuardData {
        KIntrGuard::new()
    }
}
