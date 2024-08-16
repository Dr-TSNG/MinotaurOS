use lazy_static::lazy_static;
use crate::arch::{PAGE_SIZE, PhysAddr, VirtAddr};

pub const MAX_HARTS: usize = 4;
pub const MAX_ASID: usize = 256;
pub const MAX_SYMLINKS: usize = 40;
pub const MAX_PID_DEFAULT: usize = 0x400000;

pub const KERNEL_PADDR_BASE: PhysAddr = PhysAddr(0x8020_0000);
pub const KERNEL_VADDR_BASE: VirtAddr = VirtAddr(0xFFFF_FFF0_8020_0000);
pub const KERNEL_ADDR_OFFSET: usize = KERNEL_VADDR_BASE.0 - KERNEL_PADDR_BASE.0;
pub const KERNEL_MMIO_BASE: VirtAddr = VirtAddr(0xFFFF_FFF2_0000_0000);
pub const TRAMPOLINE_BASE: VirtAddr = VirtAddr(0xFFFF_FFF1_0000_0000);
pub const DYNAMIC_LINKER_BASE: VirtAddr = VirtAddr(0x20_0000_0000);
pub const USER_LOAD_BASE: VirtAddr = VirtAddr(0x1000_0000);
pub const USER_STACK_TOP: VirtAddr = VirtAddr(0xFFFF_FFF0_8000_0000);

const KB: usize = 1024;
const MB: usize = 1024 * KB;

#[cfg(debug_assertions)]
pub const KERNEL_STACK_SIZE: usize = 1 * MB;

#[cfg(not(debug_assertions))]
pub const KERNEL_STACK_SIZE: usize = 256 * KB;

pub const KERNEL_HEAP_SIZE: usize = 48 * MB;
pub const USER_STACK_SIZE: usize = 8 * MB;
pub const USER_HEAP_SIZE_MAX: usize = 128 * MB;

pub const MAX_FD_NUM: usize = 1024;
pub const PIPE_BUF_CAP: usize = 16 * PAGE_SIZE;


extern {
    fn sbss();
    fn ebss();
    fn ekernel();
}

lazy_static! {
    pub static ref LINKAGE_ETEXT: VirtAddr = VirtAddr(ekernel as usize);
    pub static ref LINKAGE_SBSS: VirtAddr = VirtAddr(sbss as usize);
    pub static ref LINKAGE_EBSS: VirtAddr = VirtAddr(ebss as usize);
    pub static ref LINKAGE_EKERNEL: VirtAddr = VirtAddr(ekernel as usize);
}
