use alloc::string::ToString;
use log::info;
use crate::arch::{PAGE_SIZE, VirtAddr, VirtPageNum};
use crate::mm::addr_space::{AddressSpace, ASPerms};
use crate::mm::region::ASRegionMeta;
use crate::mm::region::lazy::LazyRegion;
use crate::processor::hart::local_hart;
use crate::result::SyscallResult;
use crate::sync::mutex::Mutex;
use crate::sync::once::LateInit;

pub mod asid;
pub mod addr_space;
pub mod allocator;
pub mod ffi;
pub mod page_table;
pub mod protect;
pub mod region;
mod sysv_shm;

pub static KERNEL_SPACE: LateInit<Mutex<AddressSpace>> = LateInit::new();

pub fn vm_init(primary: bool) -> SyscallResult {
    if primary {
        KERNEL_SPACE.init(Mutex::new(AddressSpace::new_kernel()));
        vm_test()?;
        info!("Kernel address space initialized");
    }
    let kernel_space = KERNEL_SPACE.lock();
    unsafe { local_hart().switch_page_table(kernel_space.token, kernel_space.root_pt); }
    Ok(())
}

fn vm_test() -> SyscallResult {
    let mut kernel_space = KERNEL_SPACE.lock();
    info!("Start VM test");
    let start = VirtPageNum(0x100);
    let region = LazyRegion::new_framed(
        ASRegionMeta {
            name: Some("VM test".to_string()),
            perms: ASPerms::R | ASPerms::W,
            start,
            pages: 4,
            offset: 0,
            dev: 0,
            ino: 0,
        },
        &[],
        0,
    )?;
    kernel_space.map_region(region);
    let slice = unsafe {
        let ptr = VirtAddr::from(VirtPageNum::from(start)).as_ptr();
        core::slice::from_raw_parts_mut(ptr, 4 * PAGE_SIZE)
    };
    unsafe { local_hart().switch_page_table(kernel_space.token, kernel_space.root_pt); }
    slice.fill(0x42);
    info!("VM test passed");
    Ok(())
}
