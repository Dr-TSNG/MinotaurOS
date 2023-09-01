use alloc::string::String;
use core::any::Any;
use core::fmt::{Debug, Display, Formatter};
use core::sync::atomic::{AtomicU64, Ordering};

pub type KoID = u64;

#[derive(Debug)]
pub enum KObjectType {
    AddressSpace,
    VMObject,
}

impl Display for KObjectType {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub trait KObject: Any + Sync + Send {
    /// Returns the unique ID of the kernel object.
    fn id(&self) -> KoID;

    /// Returns the type of the kernel object.
    fn res_type(&self) -> KObjectType;

    /// Returns the description of the kernel object.
    fn description(&self) -> String;
}

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

pub struct KObjectBase {
    pub id: KoID,
}

impl KObjectBase {
    fn new_koid() -> KoID {
        static NEXT_KOID: AtomicU64 = AtomicU64::new(0);
        NEXT_KOID.fetch_add(1, Ordering::SeqCst)
    }
}

impl Default for KObjectBase {
    fn default() -> Self {
        Self { id: Self::new_koid() }
    }
}

#[macro_export]
macro_rules! impl_kobject {
    ($type_name:path, $class:ident $( $fn:tt )*) => {
        impl KObject for $class {
            fn id(&self) -> KoID {
                self.base.id
            }
            fn res_type(&self) -> KObjectType {
                $type_name
            }
            fn description(&self) -> alloc::string::String {
                alloc::string::ToString::to_string(&$type_name)
            }
            // 可以传入任意数量的函数，覆盖 trait 的默认实现
            $( $fn )*
        }

        impl core::fmt::Debug for $class {
            fn fmt(
                &self,
                f: &mut core::fmt::Formatter<'_>,
            ) -> core::result::Result<(), core::fmt::Error> {
                f.debug_tuple(&stringify!($class))
                .field(&self.id())
                .field(&self.description())
                .finish()
            }
        }

        impl PartialEq for $class {
            fn eq(&self, other: &Self) -> bool {
                self.id() == other.id()
            }
        }

        impl Eq for $class {}
    };
}
