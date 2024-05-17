use num_enum::TryFromPrimitive;

#[derive(Debug, TryFromPrimitive)]
#[repr(i32)]
pub enum FutexOp {
    Wait = 0,
    Wake = 1,
    Requeue = 3,
    CmpRequeue = 4,
    PrivateFlag = 128,
    RealTime = 256,
}
