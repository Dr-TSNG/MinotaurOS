use crate::arch::{kvaddr_to_paddr, PhysAddr};
use crate::config::KERNEL_HEAP_END;

#[cfg(feature = "board_qemu")]
pub const HART_CNT: usize = 2;

#[cfg(feature = "board_fu740")]
pub const HART_CNT: usize = 4;

#[cfg(feature = "board_qemu")]
pub const PHYS_MEMORY: &[(PhysAddr, PhysAddr)] = &[
    (kvaddr_to_paddr(KERNEL_HEAP_END), PhysAddr(0x88000000)),
];
