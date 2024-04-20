#[cfg(feature = "board_qemu")]
mod qemu;

#[cfg(feature = "board_qemu")]
pub use qemu::*;

use alloc::vec;
use fdt_rs::base::DevTree;
use fdt_rs::index::DevTreeIndex;
use crate::arch::{PhysAddr, VirtAddr};
use crate::mm::addr_space::ASPerms;
use crate::sync::once::LateInit;

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

#[derive(Debug)]
pub struct BoardInfo {
    pub smp: usize,
}

pub static BOARD_INFO: LateInit<BoardInfo> = LateInit::new();

pub fn init(dtb_paddr: usize) {
    let mut board_info = BoardInfo {
        smp: 0,
    };
    let fdt = unsafe {
        DevTree::from_raw_pointer(dtb_paddr as *const u8).unwrap()
    };
    let layout = DevTreeIndex::get_layout(&fdt).unwrap();
    let mut buf = vec![0u8; layout.size() + layout.align()];
    let dti = DevTreeIndex::new(fdt, &mut buf).unwrap();
    for node in dti.root().children() {
        if node.name().unwrap() == "cpus" {
            for cpu in node.children() {
                if cpu.name().unwrap().starts_with("cpu@") {
                    board_info.smp += 1;
                }
            }
        }
    }
    BOARD_INFO.init(board_info);
}
