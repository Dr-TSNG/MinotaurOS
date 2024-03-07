use lazy_static::lazy_static;
use crate::arch::{PAGE_SIZE, PhysAddr, VirtAddr};

pub const MAX_HARTS: usize = 16;

pub const KERNEL_PADDR_BASE: PhysAddr = PhysAddr(0x8020_0000);
pub const KERNEL_VADDR_BASE: VirtAddr = VirtAddr(0xFFFF_FFFF_8020_0000);
pub const KERNEL_ADDR_OFFSET: usize = KERNEL_VADDR_BASE.0 - KERNEL_PADDR_BASE.0;
pub const KERNEL_MMIO_BASE: VirtAddr = VirtAddr(0xFFFF_FFFF_9000_0000);
pub const DYNAMIC_LINKER_BASE: usize = 1 << 37;

pub const KERNEL_STACK_SIZE: usize = PAGE_SIZE * 64; // 64 KB
pub const KERNEL_HEAP_SIZE: usize = PAGE_SIZE * 4096; // 4 MB
pub const KERNEL_TLS_SIZE: usize = PAGE_SIZE * 64 * MAX_HARTS; // 64 KB for each

pub const USER_STACK_SIZE: usize = PAGE_SIZE * 64; // 64 KB
pub const USER_HEAP_SIZE: usize = PAGE_SIZE * 4096; // 4 MB

pub const MAX_FD_NUM: usize = 1024;

extern {
    fn sbss();
    fn ebss();
    fn ekernel();
}

lazy_static! {
    pub static ref LINKAGE_SBSS: VirtAddr = unsafe { VirtAddr(sbss as usize) };
    pub static ref LINKAGE_EBSS: VirtAddr = unsafe { VirtAddr(ebss as usize) };
    pub static ref LINKAGE_EKERNEL: VirtAddr = unsafe { VirtAddr(ekernel as usize) };
}
