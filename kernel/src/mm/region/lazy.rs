use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use log::trace;
use crate::arch::{PageTableEntry, PhysPageNum, PTEFlags, VirtAddr, VirtPageNum};
use crate::mm::addr_space::ASPerms;
use crate::mm::allocator::{alloc_kernel_frames, alloc_user_frames, HeapFrameTracker, UserFrameTracker};
use crate::mm::page_table::{PageTable, SlotType};
use crate::mm::region::{ASRegion, ASRegionMeta};
use crate::result::{MosError, MosResult};

pub struct LazyRegion {
    metadata: ASRegionMeta,
    pages: Vec<PageState>,
}

/// 虚拟页状态
enum PageState {
    /// 页面为空，未分配物理页帧
    Free,
    /// 页面已映射
    Framed(UserFrameTracker),
    /// 写时复制
    CopyOnWrite(Arc<UserFrameTracker>)
}

impl ASRegion for LazyRegion {
    fn metadata(&self) -> &ASRegionMeta {
        &self.metadata
    }

    fn map(&self, root_pt: PageTable) -> MosResult<Vec<HeapFrameTracker>> {
        let mut dirs = vec![];
        let mut vpn = self.metadata.start;
        for page in self.pages.iter() {
            dirs.extend(self.map_one(root_pt, page, vpn)?);
            vpn = vpn + 1;
        }
        Ok(dirs)
    }

    fn unmap(&self, root_pt: PageTable) -> MosResult {
        let mut vpn = self.metadata.start;
        for _ in self.pages.iter() {
            self.unmap_one(root_pt, vpn)?;
            vpn = vpn + 1;
        }
        Ok(())
    }

    fn copy(&self) -> MosResult<Box<dyn ASRegion>> {
        todo!()
    }

    fn fault_handler(&mut self, vpn: VirtPageNum, perform: ASPerms) -> MosResult<bool> {
        todo!()
    }
}

impl LazyRegion {
    pub fn new_free(metadata: ASRegionMeta) -> Box<Self> {
        let mut pages = vec![];
        for _ in 0..metadata.pages {
            pages.push(PageState::Free);
        }
        let region = Self { metadata, pages };
        Box::new(region)
    }

    pub fn new_framed(metadata: ASRegionMeta) -> MosResult<Box<Self>> {
        let mut pages = vec![];
        for _ in 0..metadata.pages {
            let page = alloc_user_frames(1)?;
            pages.push(PageState::Framed(page));
        }
        let region = Self { metadata, pages };
        Ok(Box::new(region))
    }
}

impl LazyRegion {
    fn map_one(&self, mut pt: PageTable, page: &PageState, vpn: VirtPageNum) -> MosResult<Vec<HeapFrameTracker>> {
        let mut dirs = vec![];
        for (i, idx) in vpn.indexes().iter().enumerate() {
            let pte = pt.get_pte_mut(*idx);
            if i == 2 {
                if pte.valid() {
                    return Err(MosError::PageAlreadyMapped(pte.ppn()));
                }
                let (ppn, flags) = match page {
                    PageState::Free => (PhysPageNum(0), PTEFlags::empty()),
                    PageState::Framed(ref tracker) => {
                        let mut flags = PTEFlags::V | PTEFlags::A | PTEFlags::D | PTEFlags::U;
                        if self.metadata.perms.contains(ASPerms::R) { flags |= PTEFlags::R; }
                        if self.metadata.perms.contains(ASPerms::W) { flags |= PTEFlags::W; }
                        if self.metadata.perms.contains(ASPerms::X) { flags |= PTEFlags::X; }
                        (tracker.ppn, flags)
                    }
                    PageState::CopyOnWrite(ref tracker) => {
                        let mut flags = PTEFlags::V | PTEFlags::A | PTEFlags::D | PTEFlags::U;
                        if self.metadata.perms.contains(ASPerms::R) { flags |= PTEFlags::R; }
                        // No W
                        if self.metadata.perms.contains(ASPerms::X) { flags |= PTEFlags::X; }
                        (tracker.ppn, flags)
                    }
                };
                trace!(
                    "LazyMap: create page at lv{}pt {:?} slot {} -> {:?} - {:?} | {:?}",
                    i, pt.ppn, idx, ppn, vpn, flags,
                );
                *pte = PageTableEntry::new(ppn, flags);
                break;
            } else {
                match pt.slot_type(*idx) {
                    SlotType::Directory(next) => pt = next,
                    SlotType::Page(_) => return Err(MosError::PageAlreadyMapped(pte.ppn())),
                    SlotType::Invalid => {
                        let dir = alloc_kernel_frames(1)?;
                        trace!(
                            "LazyMap: create dir at lv{}pt {:?} slot {} -> {:?}",
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

    fn unmap_one(&self, mut pt: PageTable, vpn: VirtPageNum) -> MosResult {
        for (i, idx) in vpn.indexes().iter().enumerate() {
            let pte = pt.get_pte_mut(*idx);
            if i == 2 {
                if !pte.valid() {
                    return Err(MosError::BadAddress(VirtAddr::from(vpn)));
                }
                trace!(
                    "LazyUnmap: invalidate page at lv{}pt {:?} slot {} -> {:?}",
                    i, pt.ppn, idx, vpn,
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
