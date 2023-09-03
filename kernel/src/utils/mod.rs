#[repr(C)]
pub struct Aligned<Align, Bytes: ?Sized> {
    pub _align: [Align; 0],
    pub bytes: Bytes,
}

#[macro_export]
macro_rules! include_bytes_aligned {
    ($align_ty:ty, $file:expr $(,)?) => {
        {
            use $crate::util::Aligned;
            static ALIGNED: &Aligned::<$align_ty, [u8]> = &Aligned {
                _align: [],
                bytes: *include_bytes!($file),
            };
            &ALIGNED.bytes
        }
    };
}
