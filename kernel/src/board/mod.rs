use common::arch::PAGE_SIZE;

#[cfg(feature = "board_qemu")]
pub const HART_CNT: usize = 2;

#[cfg(feature = "board_fu740")]
pub const HART_CNT: usize = 4;

pub const KERNEL_STACK_SIZE: usize = PAGE_SIZE * 2;
