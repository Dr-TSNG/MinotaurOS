use crate::arch::{PAGE_SIZE, PhysAddr, VirtAddr};

pub const BOOTLOADER_PADDR_BASE: PhysAddr = PhysAddr(0x80200000);

pub const KERNEL_PADDR_BASE: PhysAddr = PhysAddr(0x80400000);
pub const KERNEL_VADDR_BASE: VirtAddr = VirtAddr(0xFFFFFFFF80000000);
pub const KERNEL_ADDR_OFFSET: usize = KERNEL_VADDR_BASE.0 - KERNEL_PADDR_BASE.0;
