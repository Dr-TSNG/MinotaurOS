use alloc::boxed::Box;
use alloc::sync::Weak;
use alloc::vec;
use alloc::vec::Vec;
use crate::arch::{PAGE_SIZE, PageTableEntry, PhysPageNum, PTEFlags, VirtPageNum};
use crate::fs::page_cache::PageCache;
use crate::mm::addr_space::ASPerms;
use crate::mm::allocator::{alloc_kernel_frames, HeapFrameTracker};
use crate::mm::page_table::{PageTable, SlotType};
use crate::mm::region::{ASRegion, ASRegionMeta};
use crate::result::SyscallResult;
use crate::sync::block_on;

#[derive(Clone)]
pub struct FileRegion {
    metadata: ASRegionMeta,
    page_cache: Weak<PageCache>,
    pages: Vec<PageState>,
    offset: usize,
}

#[derive(Clone)]
enum PageState {
    /// 页面为空，未绑定页缓存
    Free,
    /// 页面已绑定页缓存，未修改
    Clean,
    /// 页面已绑定页缓存，已修改
    Dirty,
}

impl ASRegion for FileRegion {
    fn metadata(&self) -> &ASRegionMeta {
        &self.metadata
    }

    fn map(&self, root_pt: PageTable, overwrite: bool) -> Vec<HeapFrameTracker> {
        let mut dirs = vec![];
        let mut vpn = self.metadata.start;
        for i in 0..self.pages.len() {
            dirs.extend(self.map_one(root_pt, i, vpn, overwrite));
            vpn = vpn + 1;
        }
        dirs
    }

    fn unmap(&self, root_pt: PageTable) {
        for i in 0..self.pages.len() {
            self.unmap_one(root_pt, i);
        }
    }

    fn resize(&mut self, _new_pages: usize) {
        panic!("Resize is not supported for file region");
    }

    fn fork(&mut self, _parent_pt: PageTable) -> Box<dyn ASRegion> {
        Box::new(self.clone())
    }

    fn fault_handler(&mut self, root_pt: PageTable, vpn: VirtPageNum) -> SyscallResult {
        let page_num = (vpn - self.metadata.start).0;
        self.pages[page_num] = match self.pages[page_num] {
            PageState::Free => PageState::Clean,
            PageState::Clean => PageState::Dirty,
            PageState::Dirty => panic!("Page should not be dirty"),
        };
        self.map_one(root_pt, page_num, vpn, true);
        Ok(())
    }
}

impl FileRegion {
    pub fn new(metadata: ASRegionMeta, page_cache: Weak<PageCache>, offset: usize) -> Box<Self> {
        let pages = vec![PageState::Free; metadata.pages];
        let region = Self { metadata, page_cache, pages, offset };
        Box::new(region)
    }

    fn map_one(
        &self,
        mut pt: PageTable,
        page_num: usize,
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
                let (ppn, flags) = match self.pages[page_num] {
                    PageState::Free => (PhysPageNum(0), PTEFlags::empty()),
                    PageState::Clean => {
                        let page_cache = self.page_cache.upgrade().unwrap();
                        block_on(page_cache.load(page_num + self.offset)).unwrap();
                        let page = page_cache.ppn_of(page_num + self.offset).unwrap();
                        let mut flags = PTEFlags::V | PTEFlags::A | PTEFlags::D | PTEFlags::U;
                        if self.metadata.perms.contains(ASPerms::R) { flags |= PTEFlags::R; }
                        // No W
                        if self.metadata.perms.contains(ASPerms::X) { flags |= PTEFlags::X; }
                        (page, flags)
                    }
                    PageState::Dirty => {
                        let page_cache = self.page_cache.upgrade().unwrap();
                        block_on(page_cache.load(page_num + self.offset)).unwrap();
                        let page = page_cache.ppn_of(page_num + self.offset).unwrap();
                        let mut flags = PTEFlags::V | PTEFlags::A | PTEFlags::D | PTEFlags::U;
                        if self.metadata.perms.contains(ASPerms::R) { flags |= PTEFlags::R; }
                        if self.metadata.perms.contains(ASPerms::W) { flags |= PTEFlags::W; }
                        if self.metadata.perms.contains(ASPerms::X) { flags |= PTEFlags::X; }
                        (page, flags)
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
        let page_cache = self.page_cache.upgrade().unwrap();
        block_on(page_cache.sync((page_num + self.offset) * PAGE_SIZE, PAGE_SIZE)).unwrap();
        let vpn = self.metadata.start + page_num;
        for (i, idx) in vpn.indexes().iter().enumerate() {
            let pte = pt.get_pte_mut(*idx);
            if i == 2 {
                pte.set_flags(PTEFlags::empty());
                break;
            } else {
                match pt.slot_type(*idx) {
                    SlotType::Directory(next) => pt = next,
                    SlotType::Page(ppn) => panic!("Page already mapped: {:?}", ppn),
                    SlotType::Invalid => panic!("Page not mapped"),
                }
            }
        }
    }
}
