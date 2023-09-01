use alloc::boxed::Box;
use crate::mm::vmas::AddressSpace;
use crate::result::MosResult;

pub fn init_root_task_address_space() -> MosResult<Box<AddressSpace>> {
    let addrs = AddressSpace::new_bare()?;
    Ok(Box::new(addrs))
}
