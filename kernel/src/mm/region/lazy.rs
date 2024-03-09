use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;
use log::trace;
use crate::arch::{PAGE_SIZE, PageTableEntry, PhysPageNum, PTEFlags, VirtAddr, VirtPageNum};
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
    CopyOnWrite(Arc<UserFrameTracker>),
}

impl ASRegion for LazyRegion {
    fn metadata(&self) -> &ASRegionMeta {
        &self.metadata
    }

    fn map(&self, root_pt: PageTable) -> MosResult<Vec<HeapFrameTracker>> {
        let mut dirs = vec![];
        let mut vpn = self.metadata.start;
        for page in self.pages.iter() {
            dirs.extend(self.map_one(root_pt, page, vpn, false)?);
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

    fn fork(&mut self, parent_pt: PageTable) -> MosResult<Box<dyn ASRegion>> {
        let mut new_pages = vec![];
        let mut remap = vec![];
        for (i, page) in self.pages.iter_mut().enumerate() {
            let mut temp = PageState::Free;
            core::mem::swap(&mut temp, page);
            let new_page = match temp {
                PageState::Free => PageState::Free,
                PageState::Framed(tracker) => {
                    remap.push(i);
                    let tracker = Arc::new(tracker);
                    temp = PageState::CopyOnWrite(tracker.clone());
                    PageState::CopyOnWrite(tracker)
                }
                PageState::CopyOnWrite(tracker) => {
                    temp = PageState::CopyOnWrite(tracker.clone());
                    PageState::CopyOnWrite(tracker)
                }
            };
            core::mem::swap(&mut temp, page);
            new_pages.push(new_page);
        }
        for i in remap {
            let vpn = self.metadata.start + i;
            self.map_one(parent_pt, &new_pages[i], vpn, true)?;
        }
        let new_region = LazyRegion {
            metadata: self.metadata.clone(),
            pages: new_pages,
        };
        Ok(Box::new(new_region))
    }

    fn fault_handler(&mut self, root_pt: PageTable, vpn: VirtPageNum) -> MosResult<()> {
        let id = vpn - self.metadata.start;
        let mut temp = PageState::Free;
        core::mem::swap(&mut temp, &mut self.pages[id.0]);
        match temp {
            PageState::Free => {
                temp = PageState::Framed(alloc_user_frames(1)?);
            }
            PageState::CopyOnWrite(tracker) => {
                let new_tracker = alloc_user_frames(1)?;
                new_tracker.ppn.byte_array().copy_from_slice(tracker.ppn.byte_array());
                temp = PageState::Framed(new_tracker);
            }
            PageState::Framed(_) => {
                panic!("This should not happen?");
                // TODO: 如果两个线程先后访问同一个页面，会发生什么？
            }
        }
        self.map_one(root_pt, &temp, vpn, true)?;
        core::mem::swap(&mut temp, &mut self.pages[id.0]);
        Ok(())
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

    pub fn new_framed(
        metadata: ASRegionMeta,
        buf: Option<&[u8]>,
    ) -> MosResult<Box<Self>> {
        if buf.is_some_and(|buf| buf.len() > metadata.pages * PAGE_SIZE) {
            return Err(MosError::CrossBoundary);
        }
        let mut pages = vec![];
        for i in 0..metadata.pages {
            let page = alloc_user_frames(1)?;
            if let Some(buf) = buf {
                let copy_start = i * PAGE_SIZE;
                if copy_start < buf.len() {
                    let copy_cnt = min(PAGE_SIZE, buf.len() - copy_start);
                    page.ppn
                        .byte_array()[0..copy_cnt]
                        .copy_from_slice(&buf[copy_start..copy_start + copy_cnt]);
                }
            }
            pages.push(PageState::Framed(page));
        }
        let region = Self { metadata, pages };
        Ok(Box::new(region))
    }
}

impl LazyRegion {
    fn map_one(
        &self,
        mut pt: PageTable,
        page: &PageState,
        vpn: VirtPageNum,
        remap: bool,
    ) -> MosResult<Vec<HeapFrameTracker>> {
        let mut dirs = vec![];
        for (i, idx) in vpn.indexes().iter().enumerate() {
            let pte = pt.get_pte_mut(*idx);
            if i == 2 {
                if !remap && pte.valid() {
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
                    SlotType::Page(ppn) => return Err(MosError::PageAlreadyMapped(ppn)),
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
