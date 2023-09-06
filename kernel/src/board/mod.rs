#[cfg(feature = "board_qemu")]
mod qemu;

#[cfg(feature = "board_qemu")]
pub use qemu::*;
