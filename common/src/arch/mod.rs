#[macro_use]
pub mod console;
mod riscv;

pub use riscv::address::{PhysAddr, PhysPageNum, VirtAddr, VirtPageNum, SimpleRange, SimpleRangeIterator, VPNRange};
pub use riscv::address::SV39_PAGE_BITS as PAGE_BITS;
pub use riscv::address::SV39_PAGE_SIZE as PAGE_SIZE;
pub use riscv::page_table::{PageTableEntry, PTEFlags};

pub fn shutdown() -> ! {
    riscv::sbi::shutdown()
}
