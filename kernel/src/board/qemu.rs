use core::fmt::Write;
use lazy_static::lazy_static;
use crate::arch::{kvaddr_to_paddr, PhysAddr, sbi};
use crate::config::LINKAGE_EKERNEL;
use crate::debug::console::Console;

pub const CONSOLE_PADDR_BASE: Option<PhysAddr> = None;

lazy_static! {
    pub static ref PHYS_MEMORY: [(PhysAddr, PhysAddr); 1] = [
        (kvaddr_to_paddr(*LINKAGE_EKERNEL), PhysAddr(0x88000000)),
    ];
}

pub struct ConsoleImpl;

impl Write for ConsoleImpl {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let _ = sbi::console_write(s);
        Ok(())
    }
}

impl Console for ConsoleImpl {}
