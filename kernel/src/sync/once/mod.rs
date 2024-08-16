use core::ops::{Deref, DerefMut};
use crate::println;

// TODO: Replace with own `Once` implementation
pub type Once<T> = spin::once::Once<T>;

#[derive(Debug, Default)]
pub struct LateInit<T>(Once<T>);

impl<T> LateInit<T> {
    pub const fn new() -> Self {
        Self(Once::new())
    }

    pub fn is_initialized(&self) -> bool {
        self.0.is_completed()
    }

    pub fn init(&self, val: T) {
        println!("lateinit init begin");
        debug_assert!(self.0.get().is_none(), "LateInit::init called twice");
        println!("lateinit init ...");
        self.0.call_once(|| val);
        println!("lateinit init down");
    }

    fn get(&self) -> &T {
        self.0.get().unwrap()
    }

    fn get_mut(&mut self) -> &mut T {
        self.0.get_mut().unwrap()
    }
}

impl<T> Deref for LateInit<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.get()
    }
}

impl<T> DerefMut for LateInit<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.get_mut()
    }
}
