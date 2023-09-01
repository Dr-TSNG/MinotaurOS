#[macro_use]
pub mod console;
mod riscv;

pub use riscv::address::{paddr_to_kvaddr, kvaddr_to_paddr, ppn_to_kvpn, kvpn_to_ppn};
pub use riscv::address::{PhysAddr, PhysPageNum, VirtAddr, VirtPageNum, SimpleRange, SimpleRangeIterator, VPNRange};
pub use riscv::address::SV39_PAGE_BITS as PAGE_BITS;
pub use riscv::address::SV39_PAGE_SIZE as PAGE_SIZE;
pub use riscv::pte::{PTE_SLOTS, PageTableEntry, PTEFlags, PTEType};

pub fn shutdown() -> ! {
    riscv::sbi::shutdown()
}
