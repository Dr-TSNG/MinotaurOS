use lazy_static::lazy_static;
use virtio_drivers::PAGE_SIZE;
use crate::arch::{kvaddr_to_paddr, PhysAddr};
use crate::board::GlobalMapping;
use crate::config::{KERNEL_MMIO_BASE, KERNEL_PADDR_BASE, KERNEL_VADDR_BASE, LINKAGE_EKERNEL};
use crate::mm::addr_space::ASPerms;

pub const CLOCK_FREQ: usize = 10000000;

lazy_static! {
    pub static ref PHYS_MEMORY: [(PhysAddr, PhysAddr); 1] = [
        (kvaddr_to_paddr(*LINKAGE_EKERNEL), PhysAddr(0x8800_0000)),
    ];

    pub static ref GLOBAL_MAPPINGS: [GlobalMapping; 2] = [
        GlobalMapping::new(
            "[kernel]",
            KERNEL_PADDR_BASE,
            KERNEL_VADDR_BASE,
            *LINKAGE_EKERNEL,
            ASPerms::R | ASPerms::W | ASPerms::X,
        ),
        GlobalMapping::new(
            "[virtio0]",
            PhysAddr(0x1000_1000),
            KERNEL_MMIO_BASE,
            KERNEL_MMIO_BASE + PAGE_SIZE,
            ASPerms::R | ASPerms::W,
        ),
    ];
}
