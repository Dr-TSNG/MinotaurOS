use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use crate::arch::{PageTableEntry, PhysPageNum, PTEFlags, VirtPageNum};
use crate::mm::addr_space::ASPerms;
use crate::mm::allocator::{alloc_kernel_frames, alloc_user_frames, HeapFrameTracker, UserFrameTracker};
use crate::mm::page_table::{PageTable, SlotType};
use crate::mm::region::{ASRegion, ASRegionMeta};
use crate::result::{Errno, SyscallResult};

#[derive(Clone)]
pub struct SharedRegion {
    metadata: ASRegionMeta,
    pages: Vec<Arc<PageState>>,
}

/// 虚拟页状态
enum PageState {
    /// 页面为空，未分配物理页帧
    Free,
    /// 页面已映射
    Framed(UserFrameTracker),
    /// 通过 `shmem` 系统调用映射的页面
    Reffed(Weak<UserFrameTracker>),
}

impl ASRegion for SharedRegion {
    fn metadata(&self) -> &ASRegionMeta {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut ASRegionMeta {
        &mut self.metadata
    }

    fn map(&self, root_pt: PageTable, overwrite: bool) -> Vec<HeapFrameTracker> {
        let mut dirs = vec![];
        let mut vpn = self.metadata.start;
        for page in self.pages.iter() {
            dirs.extend(self.map_one(root_pt, page, vpn, overwrite));
            vpn = vpn + 1;
        }
        dirs
    }

    fn unmap(&self, root_pt: PageTable) {
        let mut vpn = self.metadata.start;
        for _ in self.pages.iter() {
            self.unmap_one(root_pt, vpn);
            vpn = vpn + 1;
        }
    }

    fn split(&mut self, start: usize, size: usize) -> Vec<Box<dyn ASRegion>> {
        assert!(size < self.metadata.pages);
        assert!(start + size <= self.metadata.pages);
        let mut regions: Vec<Box<dyn ASRegion>> = vec![];
        if start != 0 {
            let mut off = self.pages.split_off(start);
            if size != 0 {
                let mid = SharedRegion {
                    metadata: ASRegionMeta {
                        start: self.metadata.start + start,
                        pages: size,
                        ..self.metadata.clone()
                    },
                    pages: off.drain(..size).collect(),
                };
                regions.push(Box::new(mid));
            }
            if !off.is_empty() {
                let right = SharedRegion {
                    metadata: ASRegionMeta {
                        start: self.metadata.start + start + size,
                        pages: self.metadata.pages - start - size,
                        ..self.metadata.clone()
                    },
                    pages: off,
                };
                regions.push(Box::new(right));
            }
            self.metadata.pages = start;
        } else {
            let off = self.pages.split_off(size);
            let right = SharedRegion {
                metadata: ASRegionMeta {
                    start: self.metadata.start + size,
                    pages: self.metadata.pages - size,
                    ..self.metadata.clone()
                },
                pages: off,
            };
            regions.push(Box::new(right));
            self.metadata.pages = size;
        }
        regions
    }

    fn extend(&mut self, size: usize) {
        self.metadata.pages += size;
        for _ in 0..size {
            self.pages.push(Arc::new(PageState::Free));
        }
    }

    fn fork(&mut self, _parent_pt: PageTable) -> Box<dyn ASRegion> {
        Box::new(self.clone())
    }

    fn fault_handler(&mut self, root_pt: PageTable, vpn: VirtPageNum) -> SyscallResult<Vec<HeapFrameTracker>> {
        let id = vpn - self.metadata.start;
        if matches!(self.pages[id].as_ref(), PageState::Free) {
            self.pages[id] = Arc::new(PageState::Framed(alloc_user_frames(1)?));
        } else {
            return Err(Errno::EFAULT);
        }
        Ok(self.map_one(root_pt, &self.pages[id], vpn, true))
    }
}

impl SharedRegion {
    pub fn new_free(metadata: ASRegionMeta) -> Box<Self> {
        let mut pages = vec![];
        for _ in 0..metadata.pages {
            pages.push(Arc::new(PageState::Free));
        }
        let region = Self { metadata, pages };
        Box::new(region)
    }

    pub fn new_reffed(
        metadata: ASRegionMeta,
        pages: &[Arc<UserFrameTracker>],
    ) -> Box<Self> {
        let pages = pages
            .iter()
            .map(|page| Arc::new(PageState::Reffed(Arc::downgrade(page))))
            .collect();
        let region = Self { metadata, pages };
        Box::new(region)
    }
}

impl SharedRegion {
    fn map_one(
        &self,
        mut pt: PageTable,
        page: &PageState,
        vpn: VirtPageNum,
        overwrite: bool,
    ) -> Vec<HeapFrameTracker> {
        let mut dirs = vec![];
        for (i, idx) in vpn.indexes().iter().enumerate() {
            let pte = pt.get_pte_mut(*idx);
            if i == 2 {
                if !overwrite && pte.valid() {
                    panic!("Page already mapped: {:?}", pte.ppn());
                }
                let (ppn, flags) = match page {
                    PageState::Free => (PhysPageNum(0), PTEFlags::empty()),
                    PageState::Framed(tracker) => {
                        let mut flags = PTEFlags::V | PTEFlags::A | PTEFlags::D | PTEFlags::U;
                        if self.metadata.perms.contains(ASPerms::R) { flags |= PTEFlags::R; }
                        if self.metadata.perms.contains(ASPerms::W) { flags |= PTEFlags::W; }
                        if self.metadata.perms.contains(ASPerms::X) { flags |= PTEFlags::X; }
                        (tracker.ppn, flags)
                    }
                    PageState::Reffed(tracker) => {
                        let tracker = tracker.upgrade().unwrap();
                        let mut flags = PTEFlags::V | PTEFlags::A | PTEFlags::D | PTEFlags::U;
                        if self.metadata.perms.contains(ASPerms::R) { flags |= PTEFlags::R; }
                        if self.metadata.perms.contains(ASPerms::W) { flags |= PTEFlags::W; }
                        if self.metadata.perms.contains(ASPerms::X) { flags |= PTEFlags::X; }
                        (tracker.ppn, flags)
                    }
                };
                *pte = PageTableEntry::new(ppn, flags);
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

    fn unmap_one(&self, mut pt: PageTable, vpn: VirtPageNum) {
        for (i, idx) in vpn.indexes().iter().enumerate() {
            let pte = pt.get_pte_mut(*idx);
            if i == 2 {
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
