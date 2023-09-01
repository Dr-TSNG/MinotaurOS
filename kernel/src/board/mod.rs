use common::arch::{kvaddr_to_paddr, paddr_to_kvaddr, PAGE_SIZE, PhysAddr, VirtAddr};

#[cfg(feature = "board_qemu")]
pub const HART_CNT: usize = 2;

#[cfg(feature = "board_fu740")]
pub const HART_CNT: usize = 4;

pub const KERNEL_STACK_SIZE: usize = PAGE_SIZE * 2;

pub const KERNEL_HEAP_END: VirtAddr = paddr_to_kvaddr(PhysAddr(0x82000000));

#[cfg(feature = "board_qemu")]
pub const PHYS_MEMORY: &[(PhysAddr, PhysAddr)] = &[
    (kvaddr_to_paddr(KERNEL_HEAP_END), PhysAddr(0x88000000)),
];
