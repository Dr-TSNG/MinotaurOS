use alloc::boxed::Box;
use alloc::string::ToString;
use log::info;
use crate::arch::{PAGE_SIZE, VirtAddr, VirtPageNum};
use crate::mm::addr_space::{AddressSpace, ASPerms};
use crate::mm::region::ASRegionMeta;
use crate::mm::region::lazy::LazyRegion;
use crate::result::MosResult;

pub fn init_root_task_address_space() -> MosResult<Box<AddressSpace>> {
    let mut addrs = AddressSpace::new_bare()?;
    unsafe { addrs.activate(); }
    info!("Root task address space activated");
    vm_test(&mut addrs)?;
    Ok(Box::new(addrs))
}

fn vm_test(addrs: &mut AddressSpace) -> MosResult {
    info!("Start VM Test");
    let start = VirtPageNum(0x100);
    let region = LazyRegion::new_framed(ASRegionMeta {
        name: Some("VM Test".to_string()),
        perms: ASPerms::R | ASPerms::W,
        start,
        pages: 4,
    })?;
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
