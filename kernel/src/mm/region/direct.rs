use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use log::trace;
use crate::arch::{PageTableEntry, PhysPageNum, PTEFlags, VirtAddr, VirtPageNum};
use crate::mm::addr_space::ASPerms;
use crate::mm::allocator::{alloc_kernel_frames, HeapFrameTracker};
use crate::mm::page_table::{PageTable, SlotType};
use crate::mm::region::{ASRegion, ASRegionMeta};
use crate::result::{MosError, MosResult};

#[derive(Clone)]
pub struct DirectRegion {
    metadata: ASRegionMeta,
    ppn: PhysPageNum,
}

impl ASRegion for DirectRegion {
    fn metadata(&self) -> &ASRegionMeta {
        &self.metadata
    }

    fn map(&self, root_pt: PageTable) -> MosResult<Vec<HeapFrameTracker>> {
        let mut dirs = vec![];
        let mut offset = 0;
        while offset < self.metadata.pages {
            let next_lv1 = VirtPageNum(offset).step_lv1().0;
            let next_vpn = self.metadata.start + next_lv1;
            let (level, next) = match next_vpn.index(2) == 0 && next_lv1 <= self.metadata.pages {
                true => (1, next_lv1),
                false => (2, offset + 1),
            };
            dirs.extend(self.map_one(root_pt, level, offset)?);
            offset = next;
        }
        Ok(dirs)
    }

    fn unmap(&self, root_pt: PageTable) -> MosResult {
        let mut offset = 0;
        while offset < self.metadata.pages {
            let next_lv1 = VirtPageNum(offset).step_lv1().0;
            let next_vpn = self.metadata.start + next_lv1;
            let (level, next) = match next_vpn.index(2) == 0 && next_lv1 <= self.metadata.pages {
                true => (1, next_lv1),
                false => (2, offset + 1),
            };
            self.unmap_one(root_pt, level, offset)?;
            offset = next;
        }
        Ok(())
    }

    fn copy(&self) -> MosResult<Box<dyn ASRegion>> {
        let other_region = self.clone();
        Ok(Box::new(other_region))
    }
}

impl DirectRegion {
    pub fn new(metadata: ASRegionMeta, ppn: PhysPageNum) -> Box<Self> {
        let region = Self { metadata, ppn };
        Box::new(region)
    }
}

impl DirectRegion {
    fn map_one(&self, mut pt: PageTable, level: usize, offset: usize) -> MosResult<Vec<HeapFrameTracker>> {
        let vpn = self.metadata.start + offset;
        let mut dirs = vec![];
        for (i, idx) in vpn.indexes().iter().enumerate() {
            let pte = pt.get_pte_mut(*idx);
            if i == level {
                if pte.valid() {
                    return Err(MosError::PageAlreadyMapped(pte.ppn()));
                }
                let mut flags = PTEFlags::V | PTEFlags::A | PTEFlags::D;
                if self.metadata.perms.contains(ASPerms::R) { flags |= PTEFlags::R; }
                if self.metadata.perms.contains(ASPerms::W) { flags |= PTEFlags::W; }
                if self.metadata.perms.contains(ASPerms::X) { flags |= PTEFlags::X; }
                trace!(
                    "DirectMap: create page at lv{}pt {:?} slot {} -> {:?} - {:?} | {:?}",
                    i, pt.ppn, idx, self.ppn + offset, vpn, flags,
                );
                *pte = PageTableEntry::new(self.ppn + offset, flags);
                break;
            } else {
                match pt.slot_type(*idx) {
                    SlotType::Directory(next) => pt = next,
                    SlotType::Page(ppn) => return Err(MosError::PageAlreadyMapped(ppn)),
                    SlotType::Invalid => {
                        let dir = alloc_kernel_frames(1)?;
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

    fn unmap_one(&self, mut pt: PageTable, level: usize, offset: usize) -> MosResult {
        let vpn = self.metadata.start + offset;
        for (i, idx) in vpn.indexes().iter().enumerate() {
            let pte = pt.get_pte_mut(*idx);
            if i == level {
                if !pte.valid() {
                    return Err(MosError::BadAddress(VirtAddr::from(vpn)));
                }
                trace!(
                    "DirectUnmap: invalidate page at lv{}pt {:?} slot {} -> {:?} - {:?}",
                    i, pt.ppn, idx, self.ppn + offset, vpn,
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
