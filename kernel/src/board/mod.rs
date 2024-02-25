#[cfg(feature = "board_qemu")]
mod qemu;

#[cfg(feature = "board_qemu")]
pub use qemu::*;

use crate::arch::{PhysAddr, VirtAddr};
use crate::mm::addr_space::ASPerms;

pub struct GlobalMapping {
    pub name: &'static str,
    pub phys_start: PhysAddr,
    pub virt_start: VirtAddr,
    pub virt_end: VirtAddr,
    pub perms: ASPerms,
}

impl GlobalMapping {
    const fn new(
        name: &'static str,
        phys_start: PhysAddr,
        virt_start: VirtAddr,
        virt_end: VirtAddr,
        perms: ASPerms,
    ) -> Self {
        Self { name, phys_start, virt_start, virt_end, perms }
    }

    pub const fn phys_end(&self) -> PhysAddr {
        PhysAddr(self.virt_end.0 - self.virt_start.0 + self.phys_start.0)
    }
}
