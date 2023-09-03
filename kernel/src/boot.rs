use alloc::boxed::Box;
use alloc::string::ToString;
use log::info;
use crate::arch::{PAGE_SIZE, VirtAddr, VirtPageNum};
use crate::mm::addr_space::{AddressSpace, ASPerms, ASRegion};
use crate::mm::vmo::lazy::VMObjectLazy;
use crate::mm::vmo::MapInfo;
use crate::result::MosResult;

pub fn init_root_task_address_space() -> MosResult<Box<AddressSpace>> {
    let mut addrs = AddressSpace::new_bare()?;
    unsafe { addrs.activate(); }
    info!("Root task address space activated");
    vmo_test(&mut addrs)?;
    Ok(Box::new(addrs))
}

fn vmo_test(addrs: &mut AddressSpace) -> MosResult {
    info!("Start VMO Test");
    let start = VirtPageNum(0x100);
    let map_info = MapInfo::new(addrs.root_pt, 2, 4, start);
    let vmo = VMObjectLazy::new_framed(map_info.clone(), ASPerms::R | ASPerms::W)?;
    let region = ASRegion::new(
        map_info,
        ASPerms::R | ASPerms::W,
        Some("VMO Test".to_string()),
        Box::new(vmo),
    );
    addrs.map_region(region)?;
    let slice = unsafe {
        let ptr = VirtAddr::from(VirtPageNum::from(start)).0 as *mut u8;
        core::slice::from_raw_parts_mut(ptr, 4 * PAGE_SIZE)
    };
    unsafe { addrs.activate(); }
    slice.fill(0x42);
    info!("Framed VMObjectLazy test passed");
    Ok(())
}
