use crate::arch::{paddr_to_kvaddr, PAGE_SIZE, PhysAddr, VirtAddr};

pub const KERNEL_PADDR_BASE: PhysAddr = PhysAddr(0x8020_0000);
pub const KERNEL_VADDR_BASE: VirtAddr = VirtAddr(0xFFFF_FFFF_8020_0000);
pub const KERNEL_ADDR_OFFSET: usize = KERNEL_VADDR_BASE.0 - KERNEL_PADDR_BASE.0;

pub const KERNEL_STACK_SIZE: usize = PAGE_SIZE * 16;

pub const KERNEL_HEAP_END: VirtAddr = paddr_to_kvaddr(PhysAddr(0x82000000));
