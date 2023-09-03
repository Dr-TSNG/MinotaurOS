use alloc::vec;
use alloc::vec::Vec;
use log::trace;
use crate::arch::{kvpn_to_ppn, PAGE_SIZE, PageTableEntry, PhysPageNum, ppn_to_kvpn, PTEFlags, VirtAddr, VirtPageNum};
use crate::mm::page_table::{PageTable, SlotType};
use crate::mm::addr_space::ASPerms;
use crate::mm::allocator::{alloc_kernel_frames, HeapFrameTracker};
use crate::mm::vmo::{MapInfo, VMObject};
use crate::result::{MosError, MosResult};

/// 直接映射：用于分配内核对象的页帧，可以直接映射到内核线性地址空间
pub struct VMObjectDirect {
    map_info: MapInfo,
    pub ppn: PhysPageNum,
    perms: ASPerms,
    _tracker: Option<HeapFrameTracker>,
}

impl VMObjectDirect {
    /// Kernel ELF 和 Kernel Heap 对象
    pub fn new_global(map_info: MapInfo, perms: ASPerms) -> Self {
        let ppn = kvpn_to_ppn(map_info.start);
        Self {
            map_info,
            ppn,
            perms,
            _tracker: None,
        }
    }

    /// 创建页目录
    pub fn new_page_dir() -> MosResult<Self> {
        let tracker = alloc_kernel_frames(1)?;
        let ppn = tracker.ppn;
        let map_info = MapInfo::new(PageTable::empty(), 2, 1, VirtPageNum(0));
        let mut obj = Self {
            map_info,
            ppn,
            perms: ASPerms::empty(),
            _tracker: Some(tracker),
        };
        obj.get_slice_mut().fill(0);
        Ok(obj)
    }

    fn get_slice_mut(&mut self) -> &mut [u8] {
        unsafe {
            let vpn = ppn_to_kvpn(self.ppn);
            let ptr = VirtAddr::from(vpn).0 as *mut u8;
            let len = self.map_info.pages * PAGE_SIZE;
            core::slice::from_raw_parts_mut(ptr, len)
        }
    }
}

impl VMObject for VMObjectDirect {
    fn set_perms(&mut self, perms: ASPerms) -> MosResult {
        self.perms = perms;
        Ok(())
    }

    fn map(&self) -> MosResult<Vec<VMObjectDirect>> {
        let vpn = self.map_info.start;
        let mut pt = self.map_info.root_pt;
        let mut dirs = vec![];
        for (i, idx) in vpn.indexes().iter().enumerate() {
            let pte = pt.get_pte_mut(*idx);
            if i == self.map_info.level {
                if pte.valid() {
                    return Err(MosError::PageAlreadyMapped(pte.ppn()));
                }
                let mut flags = PTEFlags::V | PTEFlags::A | PTEFlags::D;
                if self.perms.contains(ASPerms::R) { flags |= PTEFlags::R; }
                if self.perms.contains(ASPerms::W) { flags |= PTEFlags::W; }
                if self.perms.contains(ASPerms::X) { flags |= PTEFlags::X; }
                trace!(
                    "DirectMap: create page at lv{}pt {:?} slot {} -> {:?} - {:?} | {:?}",
                    i, pt.ppn, idx, self.ppn, vpn, flags,
                );
                *pte = PageTableEntry::new(self.ppn, flags);
                break;
            } else {
                match pt.slot_type(*idx) {
                    SlotType::Directory(next) => pt = next,
                    SlotType::Page(_) => return Err(MosError::PageAlreadyMapped(pte.ppn())),
                    SlotType::Invalid => {
                        let dir = VMObjectDirect::new_page_dir()?;
                        trace!(
                            "DirectMap: create dir at lv{}pt {:?} slot {} -> {:?}",
                            i, pt.ppn, idx, dir.ppn,
                        );
                        *pte = PageTableEntry::new(dir.ppn, PTEFlags::V);
                        pt = PageTable::new(dir.ppn);
                        dirs.push(dir);
                    }
                }
            }
        }
        Ok(dirs)
    }

    fn unmap(&self) -> MosResult {
        let vpn = self.map_info.start;
        let mut pt = self.map_info.root_pt;
        for (i, idx) in vpn.indexes().iter().enumerate() {
            let pte = pt.get_pte_mut(*idx);
            if i == self.map_info.level {
                if !pte.valid() {
                    return Err(MosError::BadAddress(VirtAddr::from(vpn)));
                }
                trace!(
                    "DirectUnmap: invalidate page at lv{}pt {:?} slot {} -> {:?} - {:?}",
                    i, pt.ppn, idx, self.ppn, vpn,
                );
                pte.set_flags(PTEFlags::empty());
                break;
            } else {
                match pt.slot_type(*idx) {
                    SlotType::Directory(next) => pt = next,
                    _ => return Err(MosError::BadAddress(VirtAddr::from(vpn))),
                }
            }
        }
        Ok(())
    }
}
