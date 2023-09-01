use alloc::format;
use alloc::string::String;
use core::fmt::Debug;
use log::trace;
use common::arch::{kvpn_to_ppn, PAGE_SIZE, PageTableEntry, PhysPageNum, PTEFlags, VirtAddr, VirtPageNum};
use crate::kobject::{KObject, KObjectType, KoID};
use crate::mm::allocator::heap;
use crate::mm::page_table::SlotType;
use crate::mm::vmas::{AddressSpace, ASPerms};
use crate::mm::vmo::VMObject;
use crate::result::{MosError, MosResult};

/// 直接映射：用于分配内核对象的页帧，可以直接映射到内核线性地址空间
#[derive(Debug)]
pub struct VMObjectDirect {
    pub ppn: PhysPageNum,
    vpn: VirtPageNum,
    perms: ASPerms,
}

impl VMObjectDirect {
    pub fn new(perms: ASPerms) -> MosResult<Self> {
        let vpn = heap::alloc_kernel_pages(1)?;
        let ppn = kvpn_to_ppn(vpn);
        Ok(Self { vpn, ppn, perms })
    }

    fn get_slice(&self) -> &[u8] {
        unsafe {
            let ptr = VirtAddr::from(self.vpn).0 as *const u8;
            core::slice::from_raw_parts(ptr, PAGE_SIZE)
        }
    }

    fn get_slice_mut(&mut self) -> &mut [u8] {
        unsafe {
            let ptr = VirtAddr::from(self.vpn).0 as *mut u8;
            core::slice::from_raw_parts_mut(ptr, PAGE_SIZE)
        }
    }
}

impl Drop for VMObjectDirect {
    fn drop(&mut self) {
        heap::dealloc_kernel_pages(self.vpn, PAGE_SIZE).unwrap();
    }
}

impl KObject for VMObjectDirect {
    fn id(&self) -> KoID {
        todo!()
    }

    fn res_type(&self) -> KObjectType {
        todo!()
    }

    fn description(&self) -> String {
        todo!()
    }
}

impl VMObject for VMObjectDirect {
    fn detail(&self) -> String {
        format!("D[ppn: {}]", self.vpn)
    }

    fn read(&self, offset: usize, buf: &mut [u8]) -> MosResult {
        if offset + buf.len() > PAGE_SIZE {
            return Err(MosError::CrossPageBoundary);
        }
        let slice = self.get_slice();
        buf.copy_from_slice(&slice[offset..offset + buf.len()]);
        Ok(())
    }

    fn write(&mut self, offset: usize, buf: &[u8]) -> MosResult {
        if offset + buf.len() > PAGE_SIZE {
            return Err(MosError::CrossPageBoundary);
        }
        let slice = self.get_slice_mut();
        slice[offset..offset + buf.len()].copy_from_slice(buf);
        Ok(())
    }

    fn map(&self, addrs: &mut AddressSpace, vpn: VirtPageNum) -> MosResult {
        let mut pt = addrs.root_pt;
        for (i, idx) in vpn.indexes().iter().enumerate() {
            let pte = pt.get_pte_mut(*idx);
            if i == 2 {
                if pte.valid() {
                    return Err(MosError::PageAlreadyMapped);
                }
                let mut flags = PTEFlags::V | PTEFlags::A | PTEFlags::D;
                if self.perms.contains(ASPerms::R) { flags |= PTEFlags::R; }
                if self.perms.contains(ASPerms::W) { flags |= PTEFlags::W; }
                if self.perms.contains(ASPerms::X) { flags |= PTEFlags::X; }
                *pte = PageTableEntry::new(self.ppn, flags);
            } else {
                match pt.slot_type(*idx) {
                    SlotType::Directory(next) => pt = next,
                    SlotType::Page(_) => return Err(MosError::PageAlreadyMapped),
                    SlotType::Invalid => {
                        let page = VMObjectDirect::new(ASPerms::empty())?;
                        *pte = PageTableEntry::new(page.ppn, PTEFlags::V);
                        addrs.insert_pt(page);
                    }
                }
            }
        }
        trace!("DirectMap: {:?} -> {:?}", self.ppn, vpn);
        Ok(())
    }

    fn unmap(&self, addrs: &mut AddressSpace, vpn: VirtPageNum) -> MosResult {
        let mut pt = addrs.root_pt;
        for (i, idx) in vpn.indexes().iter().enumerate() {
            let pte = pt.get_pte_mut(*idx);
            if i == 2 {
                if !pte.valid() {
                    return Err(MosError::InvalidAddress);
                }
                pte.set_flags(PTEFlags::empty());
            } else {
                match pt.slot_type(*idx) {
                    SlotType::Directory(next) => pt = next,
                    _ => return Err(MosError::InvalidAddress),
                }
            }
        }
        trace!("DirectUnmap: {:?} -> {:?}", self.ppn, vpn);
        Ok(())
    }
}
