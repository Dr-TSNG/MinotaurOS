mod rv64;

use riscv::register::sie;
pub use rv64::address::SV39_PAGE_SIZE as PAGE_SIZE;
pub use rv64::address::{kvaddr_to_paddr, kvpn_to_ppn, paddr_to_kvaddr, ppn_to_kvpn};
pub use rv64::address::{PhysAddr, PhysPageNum, VirtAddr, VirtPageNum};
pub use rv64::pte::{PTEFlags, PTEType, PageTableEntry, PTE_SLOTS};
pub use rv64::sbi;

pub fn set_timer(timer: usize) {
    sbi::set_timer(timer).unwrap();
}

pub fn enable_timer_interrupt() {
    unsafe {
        sie::set_stimer();
    }
}

pub fn hardware_ts() -> usize {
    riscv::register::time::read()
}

pub fn shutdown() -> ! {
    sbi::shutdown().unwrap()
}
