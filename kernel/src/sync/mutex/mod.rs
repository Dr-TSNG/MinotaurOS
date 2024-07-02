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
pub type MutexGuard<'a, T> = spin::SpinMutexGuard<'a, T, DefaultStrategy>;
pub type IrqMutex<T> = spin::SpinMutex<T, IrqStrategy>;
pub type ReMutex<T> = reentrant::ReMutex<T, DefaultStrategy>;
pub type IrqReMutex<T> = reentrant::ReMutex<T, IrqStrategy>;
pub type AsyncMutex<T> = sync::AsyncMutex<T, DefaultStrategy>;
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

pub type SpinNoIrqLock<T> = spin::SpinMutex<T, SpinNoIrq>;

/// SpinNoIrq MutexSupport
pub struct SpinNoIrq;
/// Low-level support for mutex(spinlock, sleeplock, etc)
pub trait MutexSupport {
    /// Guard data
    type GuardData;
    /// Called before lock() & try_lock()
    fn before_lock() -> Self::GuardData;
    /// Called when MutexGuard dropping
    fn after_unlock(_: &mut Self::GuardData);
}

impl MutexStrategy for SpinNoIrq{
    type GuardData = SieGuard;

    fn new_guard() -> Self::GuardData {
        SieGuard::new()
    }
}

/// Sie Guard
pub struct SieGuard(bool);

impl SieGuard {
    /// Construct a SieGuard
    pub fn new() -> Self {
        Self(unsafe {
            let sie_before = sstatus::read().sie();
            sstatus::clear_sie();
            sie_before
        })
    }
}
impl Drop for SieGuard {
    fn drop(&mut self) {
        if self.0 {
            unsafe {
                sstatus::set_sie();
            }
        }
    }
}
