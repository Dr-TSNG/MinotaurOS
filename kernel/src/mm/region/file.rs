use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use crate::arch::{PAGE_SIZE, PageTableEntry, PhysPageNum, PTEFlags, VirtPageNum};
use crate::fs::page_cache::PageCache;
use crate::mm::addr_space::ASPerms;
use crate::mm::allocator::{alloc_kernel_frames, alloc_user_frames, HeapFrameTracker, UserFrameTracker};
use crate::mm::page_table::{PageTable, SlotType};
use crate::mm::region::{ASRegion, ASRegionMeta};
use crate::result::SyscallResult;
use crate::sync::block_on;

pub struct FileRegion {
    metadata: ASRegionMeta,
    cache: Arc<PageCache>,
    pages: Vec<PageState>,
    offset: usize,
    is_shared: bool,
}

enum PageState {
    /// 页面为空，未绑定页缓存
    Free,
    /// 页面已绑定页缓存，未修改
    Clean,
    /// 页面已绑定页缓存，已修改
    Dirty,
    /// 页面已修改，不可写回
    Private(UserFrameTracker),
    /// 页面已修改，不可写回，写时复制
    CopyOnWrite(Arc<UserFrameTracker>),
}

impl ASRegion for FileRegion {
    fn metadata(&self) -> &ASRegionMeta {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut ASRegionMeta {
        &mut self.metadata
    }

    fn map(&self, root_pt: PageTable, overwrite: bool) -> Vec<HeapFrameTracker> {
        let mut dirs = vec![];
        for i in 0..self.pages.len() {
            if overwrite || !matches!(self.pages[i], PageState::Free) {
                dirs.extend(self.map_one(root_pt, i, overwrite));
            }
        }
        dirs
    }

    fn unmap(&self, root_pt: PageTable) {
        for i in 0..self.pages.len() {
            if !matches!(self.pages[i], PageState::Free) {
                self.unmap_one(root_pt, i);
            }
        }
    }

    fn split(&mut self, start: usize, size: usize) -> Vec<Box<dyn ASRegion>> {
        assert!(size < self.metadata.pages);
        assert!(start + size <= self.metadata.pages);
        let mut regions: Vec<Box<dyn ASRegion>> = vec![];
        if start != 0 {
            let mut off = self.pages.split_off(start);
            if size != 0 {
                let mid = FileRegion {
                    metadata: ASRegionMeta {
                        start: self.metadata.start + start,
                        pages: size,
                        ..self.metadata.clone()
                    },
                    cache: self.cache.clone(),
                    pages: off.drain(..size).collect(),
                    offset: self.offset + start,
                    is_shared: self.is_shared,
                };
                regions.push(Box::new(mid));
            }
            if !off.is_empty() {
                let right = FileRegion {
                    metadata: ASRegionMeta {
                        start: self.metadata.start + start + size,
                        pages: self.metadata.pages - start - size,
                        ..self.metadata.clone()
                    },
                    cache: self.cache.clone(),
                    pages: off,
                    offset: self.offset + start + size,
                    is_shared: self.is_shared,
                };
                regions.push(Box::new(right));
            }
            self.metadata.pages = start;
        } else {
            let off = self.pages.split_off(size);
            let right = FileRegion {
                metadata: ASRegionMeta {
                    start: self.metadata.start + size,
                    pages: self.metadata.pages - size,
                    ..self.metadata.clone()
                },
                cache: self.cache.clone(),
                pages: off,
                offset: self.offset + size,
                is_shared: self.is_shared,
            };
            regions.push(Box::new(right));
            self.metadata.pages = size;
        }
        regions
    }

    fn extend(&mut self, _size: usize) {
        panic!("FileRegion cannot be extended");
    }

    fn fork(&mut self, parent_pt: PageTable) -> Box<dyn ASRegion> {
        let mut new_pages = vec![];
        let mut remap = vec![];
        for (i, page) in self.pages.iter_mut().enumerate() {
            let mut temp = PageState::Free;
            core::mem::swap(&mut temp, page);
            let new_page = match temp {
                PageState::Free => PageState::Free,
                PageState::Clean => PageState::Clean,
                PageState::Dirty => PageState::Dirty,
                PageState::Private(tracker) => {
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
            self.map_one(parent_pt, i, true);
        }
        let new_region = FileRegion {
            metadata: self.metadata.clone(),
            cache: self.cache.clone(),
            pages: new_pages,
            offset: self.offset,
            is_shared: self.is_shared,
        };
        Box::new(new_region)
    }

    fn sync(&self) {
        block_on(self.cache.sync_all()).unwrap();
    }

    fn fault_handler(&mut self, root_pt: PageTable, vpn: VirtPageNum) -> SyscallResult<Vec<HeapFrameTracker>> {
        let page_num = vpn - self.metadata.start;
        let mut temp = PageState::Free;
        core::mem::swap(&mut temp, &mut self.pages[page_num]);
        match temp {
            PageState::Free => temp = PageState::Clean,
            PageState::Clean => {
                if self.is_shared {
                    temp = PageState::Dirty;
                } else {
                    let frame = alloc_user_frames(1)?;
                    let page = self.cache.ppn_of(page_num + self.offset).unwrap();
                    frame.ppn.byte_array().copy_from_slice(page.byte_array());
                    temp = PageState::Private(frame);
                }
            }
            PageState::Dirty => panic!("Page should not be dirty"),
            PageState::Private(_) => panic!("Page should not be private"),
            PageState::CopyOnWrite(tracker) => {
                let new_tracker = alloc_user_frames(1)?;
                new_tracker.ppn.byte_array().copy_from_slice(tracker.ppn.byte_array());
                temp = PageState::Private(new_tracker);
            }
        }
        core::mem::swap(&mut temp, &mut self.pages[page_num]);
        Ok(self.map_one(root_pt, page_num, true))
    }
}

impl FileRegion {
    pub fn new(metadata: ASRegionMeta, cache: Arc<PageCache>, offset: usize, is_shared: bool) -> Box<Self> {
        let mut pages = vec![];
        for _ in 0..metadata.pages {
            pages.push(PageState::Free);
        }
        let region = Self { metadata, cache, pages, offset, is_shared };
        Box::new(region)
    }

    fn map_one(
        &self,
        mut pt: PageTable,
        page_num: usize,
        overwrite: bool,
    ) -> Vec<HeapFrameTracker> {
        let mut dirs = vec![];
        let vpn = self.metadata.start + page_num;
        for (i, idx) in vpn.indexes().iter().enumerate() {
            let pte = pt.get_pte_mut(*idx);
            if i == 2 {
                if !overwrite && pte.valid() {
                    panic!("Page already mapped: {:?}", pte.ppn());
                }
                let (ppn, flags) = match &self.pages[page_num] {
                    PageState::Free => (PhysPageNum(0), PTEFlags::empty()),
                    PageState::Clean => {
                        block_on(self.cache.load(page_num + self.offset)).unwrap();
                        let page = self.cache.ppn_of(page_num + self.offset).unwrap();
                        let mut flags = PTEFlags::V | PTEFlags::A | PTEFlags::D | PTEFlags::U;
                        if self.metadata.perms.contains(ASPerms::R) { flags |= PTEFlags::R; }
                        // No W
                        if self.metadata.perms.contains(ASPerms::X) { flags |= PTEFlags::X; }
                        (page, flags)
                    }
                    PageState::Dirty => {
                        block_on(self.cache.load(page_num + self.offset)).unwrap();
                        let page = self.cache.ppn_of(page_num + self.offset).unwrap();
                        let mut flags = PTEFlags::V | PTEFlags::A | PTEFlags::D | PTEFlags::U;
                        if self.metadata.perms.contains(ASPerms::R) { flags |= PTEFlags::R; }
                        if self.metadata.perms.contains(ASPerms::W) { flags |= PTEFlags::W; }
                        if self.metadata.perms.contains(ASPerms::X) { flags |= PTEFlags::X; }
                        (page, flags)
                    }
                    PageState::Private(tracker) => {
                        let mut flags = PTEFlags::V | PTEFlags::A | PTEFlags::D | PTEFlags::U;
                        if self.metadata.perms.contains(ASPerms::R) { flags |= PTEFlags::R; }
                        if self.metadata.perms.contains(ASPerms::W) { flags |= PTEFlags::W; }
                        if self.metadata.perms.contains(ASPerms::X) { flags |= PTEFlags::X; }
                        (tracker.ppn, flags)
                    }
                    PageState::CopyOnWrite(tracker) => {
                        let mut flags = PTEFlags::V | PTEFlags::A | PTEFlags::D | PTEFlags::U;
                        if self.metadata.perms.contains(ASPerms::R) { flags |= PTEFlags::R; }
                        // No W
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

    fn unmap_one(&self, mut pt: PageTable, page_num: usize) {
        block_on(self.cache.sync((page_num + self.offset) * PAGE_SIZE, PAGE_SIZE)).unwrap();
        let vpn = self.metadata.start + page_num;
        for (i, idx) in vpn.indexes().iter().enumerate() {
            let pte = pt.get_pte_mut(*idx);
            if i == 2 {
                pte.set_flags(PTEFlags::empty());
                break;
            } else {
                match pt.slot_type(*idx) {
                    SlotType::Directory(next) => pt = next,
                    SlotType::Page(_) => panic!("WTF big page"),
                    SlotType::Invalid => return,
                }
            }
        }
    }
}

impl Drop for FileRegion {
    fn drop(&mut self) {
        self.sync();
    }
}
