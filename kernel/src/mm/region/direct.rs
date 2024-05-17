use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use crate::arch::{PageTableEntry, PhysPageNum, PTEFlags, VirtPageNum};
use crate::mm::addr_space::ASPerms;
use crate::mm::allocator::{alloc_kernel_frames, HeapFrameTracker};
use crate::mm::page_table::{PageTable, SlotType};
use crate::mm::region::{ASRegion, ASRegionMeta};

#[derive(Clone)]
pub struct DirectRegion {
    metadata: ASRegionMeta,
    ppn: PhysPageNum,
}

impl ASRegion for DirectRegion {
    fn metadata(&self) -> &ASRegionMeta {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut ASRegionMeta {
        &mut self.metadata
    }

    fn map(&self, root_pt: PageTable, overwrite: bool) -> Vec<HeapFrameTracker> {
        let mut dirs = vec![];
        let mut offset = 0;
        while offset < self.metadata.pages {
            let next_lv1 = VirtPageNum(offset).step_lv1().0;
            let next_vpn = self.metadata.start + next_lv1;
            let (level, next) = match next_vpn.index(2) == 0 && next_lv1 <= self.metadata.pages {
                true => (1, next_lv1),
                false => (2, offset + 1),
            };
            dirs.extend(self.map_one(root_pt, level, offset, overwrite));
            offset = next;
        }
        dirs
    }

    fn unmap(&self, root_pt: PageTable) {
        let mut offset = 0;
        while offset < self.metadata.pages {
            let next_lv1 = VirtPageNum(offset).step_lv1().0;
            let next_vpn = self.metadata.start + next_lv1;
            let (level, next) = match next_vpn.index(2) == 0 && next_lv1 <= self.metadata.pages {
                true => (1, next_lv1),
                false => (2, offset + 1),
            };
            self.unmap_one(root_pt, level, offset);
            offset = next;
        }
    }

    fn resize(&mut self, new_pages: usize) {
        self.metadata.pages = new_pages;
    }

    fn fork(&mut self, _parent_pt: PageTable) -> Box<dyn ASRegion> {
        Box::new(self.clone())
    }
}

impl DirectRegion {
    pub fn new(metadata: ASRegionMeta, ppn: PhysPageNum) -> Box<Self> {
        let region = Self { metadata, ppn };
        Box::new(region)
    }
}

impl DirectRegion {
    fn map_one(&self, mut pt: PageTable, level: usize, offset: usize, overwrite: bool) -> Vec<HeapFrameTracker> {
        let vpn = self.metadata.start + offset;
        let mut dirs = vec![];
        for (i, idx) in vpn.indexes().iter().enumerate() {
            let pte = pt.get_pte_mut(*idx);
            if i == level {
                if !overwrite && pte.valid() {
                    panic!("Page already mapped: {:?}", pte.ppn());
                }
                let mut flags = PTEFlags::V | PTEFlags::A | PTEFlags::D;
                if self.metadata.perms.contains(ASPerms::R) { flags |= PTEFlags::R; }
                if self.metadata.perms.contains(ASPerms::W) { flags |= PTEFlags::W; }
                if self.metadata.perms.contains(ASPerms::X) { flags |= PTEFlags::X; }
                *pte = PageTableEntry::new(self.ppn + offset, flags);
                break;
            } else {
                match pt.slot_type(*idx) {
                    SlotType::Directory(next) => pt = next,
                    SlotType::Page(ppn) => panic!("Page already mapped: {:?}", ppn),
                    SlotType::Invalid => {
                        let dir = alloc_kernel_frames(1);
                        *pte = PageTableEntry::new(dir.ppn, PTEFlags::V);
                        pt = PageTable::new(dir.ppn);
                        dirs.push(dir);
                    }
                }
            }
        }
        dirs
    }

    fn unmap_one(&self, mut pt: PageTable, level: usize, offset: usize) {
        let vpn = self.metadata.start + offset;
        for (i, idx) in vpn.indexes().iter().enumerate() {
            let pte = pt.get_pte_mut(*idx);
            if i == level {
                if !pte.valid() {
                    panic!("Page not mapped: {:?}", pte.ppn());
                }
                pte.set_flags(PTEFlags::empty());
                break;
            } else {
                match pt.slot_type(*idx) {
                    SlotType::Directory(next) => pt = next,
                    _ => panic!("Page not mapped: {:?}", pte.ppn()),
                }
            }
        }
    }
}
