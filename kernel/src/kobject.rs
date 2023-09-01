use alloc::string::String;
use core::fmt::{Debug, Formatter};
use core::sync::atomic::{AtomicU64, Ordering};
use downcast_rs::{DowncastSync, impl_downcast};

pub type KoID = u64;

pub fn new_koid() -> KoID {
    static NEXT_KOID: AtomicU64 = AtomicU64::new(0);
    NEXT_KOID.fetch_add(1, Ordering::SeqCst)
}

#[derive(Debug)]
pub enum KObjectType {
    AddressSpace,
    VMObject,
}

pub trait KObject: DowncastSync {
    /// Returns the unique ID of the kernel object.
    fn id(&self) -> KoID;

    /// Returns the type of the kernel object.
    fn res_type(&self) -> KObjectType;

    /// Returns the description of the kernel object.
    fn description(&self) -> String;
}
impl_downcast!(sync KObject);

impl Debug for dyn KObject {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!(
            "Ko[{:#x}, {:?}] ({})",
            self.id(),
            self.res_type(),
            self.description()
        ))
    }
}
