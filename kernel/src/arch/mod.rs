#[macro_use]
pub mod console;
mod rv64;

pub use rv64::address::{paddr_to_kvaddr, kvaddr_to_paddr, ppn_to_kvpn, kvpn_to_ppn};
pub use rv64::address::{PhysAddr, PhysPageNum, VirtAddr, VirtPageNum, SimpleRange, SimpleRangeIterator, VPNRange};
pub use rv64::address::SV39_PAGE_BITS as PAGE_BITS;
pub use rv64::address::SV39_PAGE_SIZE as PAGE_SIZE;
pub use rv64::address::SV39_VPN_BITS as VPN_BITS;
pub use rv64::pte::{PTE_SLOTS, PageTableEntry, PTEFlags, PTEType};

pub fn shutdown() -> ! {
    rv64::sbi::shutdown()
}
