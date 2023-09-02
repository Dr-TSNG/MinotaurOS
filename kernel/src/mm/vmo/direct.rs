use alloc::vec;
use alloc::vec::Vec;
use log::trace;
use common::arch::{kvpn_to_ppn, PAGE_SIZE, PageTableEntry, PhysPageNum, ppn_to_kvpn, PTEFlags, VirtAddr, VirtPageNum, VPN_BITS};
use crate::impl_kobject;
use crate::kobject::{KObject, KObjectBase, KObjectType, KoID};
use crate::mm::allocator::heap;
use crate::mm::allocator::heap::HeapFrameTracker;
use crate::mm::page_table::{PageTable, SlotType};
use crate::mm::addr_space::ASPerms;
use crate::mm::vmo::VMObject;
use crate::result::{MosError, MosResult};

/// 直接映射：用于分配内核对象的页帧，可以直接映射到内核线性地址空间
pub struct VMObjectDirect {
    base: KObjectBase,
    level: usize,
    pages: usize,
    pub ppn: PhysPageNum,
    pub vpn: VirtPageNum,
    perms: ASPerms,
    _tracker: Option<HeapFrameTracker>,
}
impl_kobject!(KObjectType::VMObject, VMObjectDirect);

impl VMObjectDirect {
    /// Kernel ELF 和 Kernel Heap 对象
    pub fn new_global(level: usize, vpn: VirtPageNum, perms: ASPerms) -> Self {
        let pages = 1 << ((2 - level) * VPN_BITS);
        let ppn = kvpn_to_ppn(vpn);
        Self {
            base: KObjectBase::default(),
            level, pages, vpn, ppn, perms,
            _tracker: None,
        }
    }

    /// 从堆中分配一个新的直接映射对象
    pub fn zeroed(level: usize, perms: ASPerms) -> MosResult<Self> {
        let pages = 1 << ((2 - level) * VPN_BITS);
        let tracker = heap::alloc_kernel_frames(pages)?;
        let ppn = tracker.ppn;
        let vpn = ppn_to_kvpn(ppn);
        let mut obj = Self {
            base: KObjectBase::default(),
            level, pages, vpn, ppn, perms,
            _tracker: Some(tracker),
        };
        obj.get_slice_mut().fill(0);
        Ok(obj)
    }

    fn get_slice(&self) -> &[u8] {
        unsafe {
            let ptr = VirtAddr::from(self.vpn).0 as *const u8;
            core::slice::from_raw_parts(ptr, self.len())
        }
    }

    fn get_slice_mut(&mut self) -> &mut [u8] {
        unsafe {
            let ptr = VirtAddr::from(self.vpn).0 as *mut u8;
            core::slice::from_raw_parts_mut(ptr, self.len())
        }
    }
}

impl VMObject for VMObjectDirect {
    fn len(&self) -> usize {
        self.pages * PAGE_SIZE
    }

    fn read(&self, offset: usize, buf: &mut [u8]) -> MosResult {
        if offset + buf.len() > self.len() {
            return Err(MosError::CrossPageBoundary);
        }
        let slice = self.get_slice();
        buf.copy_from_slice(&slice[offset..offset + buf.len()]);
        Ok(())
    }

    fn write(&mut self, offset: usize, buf: &[u8]) -> MosResult {
        if offset + buf.len() > self.len() {
            return Err(MosError::CrossPageBoundary);
        }
        let slice = self.get_slice_mut();
        slice[offset..offset + buf.len()].copy_from_slice(buf);
        Ok(())
    }

    fn map(&self, mut pt: PageTable, vpn: VirtPageNum) -> MosResult<Vec<VMObjectDirect>> {
        let mut dirs = vec![];
        for (i, idx) in vpn.indexes().iter().enumerate() {
            let pte = pt.get_pte_mut(*idx);
            if i == self.level {
                if pte.valid() {
                    return Err(MosError::PageAlreadyMapped(pte.ppn()));
                }
                let mut flags = PTEFlags::V | PTEFlags::A | PTEFlags::D;
                if self.perms.contains(ASPerms::R) { flags |= PTEFlags::R; }
                if self.perms.contains(ASPerms::W) { flags |= PTEFlags::W; }
                if self.perms.contains(ASPerms::X) { flags |= PTEFlags::X; }
                trace!(
                    "DirectMap: create page at lv{}pt {:?} slot {} -> {:?} - {:?}",
                    i, pt.ppn, idx, self.ppn, self.vpn,
                );
                *pte = PageTableEntry::new(self.ppn, flags);
                break;
            } else {
                match pt.slot_type(*idx) {
                    SlotType::Directory(next) => pt = next,
                    SlotType::Page(_) => return Err(MosError::PageAlreadyMapped(pte.ppn())),
                    SlotType::Invalid => {
                        let page = VMObjectDirect::zeroed(2, ASPerms::empty())?;
                        trace!(
                            "DirectMap: create dir at lv{}pt {:?} slot {} -> {:?}",
                            i, pt.ppn, idx, page.ppn,
                        );
                        *pte = PageTableEntry::new(page.ppn, PTEFlags::V);
                        pt = PageTable::new(page.ppn);
                        dirs.push(page);
                    }
                }
            }
        }
        Ok(dirs)
    }

    fn unmap(&self, mut pt: PageTable, vpn: VirtPageNum) -> MosResult {
        for (i, idx) in vpn.indexes().iter().enumerate() {
            let pte = pt.get_pte_mut(*idx);
            if i == self.level {
                if !pte.valid() {
                    return Err(MosError::InvalidAddress);
                }
                trace!(
                    "DirectUnmap: invalidate page at lv{}pt {:?} slot {} -> {:?} - {:?}",
                    i, pt.ppn, idx, self.ppn, self.vpn,
                );
                pte.set_flags(PTEFlags::empty());
                break;
            } else {
                match pt.slot_type(*idx) {
                    SlotType::Directory(next) => pt = next,
                    _ => return Err(MosError::InvalidAddress),
                }
            }
        }
        Ok(())
    }
}
