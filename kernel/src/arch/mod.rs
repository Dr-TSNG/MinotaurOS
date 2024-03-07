mod rv64;

use riscv::register::sie;
pub use rv64::address::{paddr_to_kvaddr, kvaddr_to_paddr, ppn_to_kvpn, kvpn_to_ppn};
pub use rv64::address::{PhysAddr, PhysPageNum, VirtAddr, VirtPageNum};
pub use rv64::address::SV39_PAGE_SIZE as PAGE_SIZE;
pub use rv64::pte::{PTE_SLOTS, PageTableEntry, PTEFlags, PTEType};
pub use rv64::sbi;

pub fn set_timer(timer: usize) {
    sbi::set_timer(timer).unwrap();
}

pub fn enable_timer_interrupt() {
    unsafe { sie::set_stimer(); }
}

pub fn hardware_ts() -> usize {
    riscv::register::time::read()
}

pub fn shutdown() -> ! {
    sbi::shutdown().unwrap()
}
