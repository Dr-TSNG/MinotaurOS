use alloc::boxed::Box;
use alloc::sync::Weak;
use alloc::vec::Vec;
use crate::arch::VirtPageNum;
use crate::fs::page_cache::PageCache;
use crate::mm::allocator::HeapFrameTracker;
use crate::mm::page_table::PageTable;
use crate::mm::region::{ASRegion, ASRegionMeta};
use crate::result::SyscallResult;

pub struct FileRegion {
    metadata: ASRegionMeta,
    page_cache: Weak<PageCache>,
}

impl ASRegion for FileRegion {
    fn metadata(&self) -> &ASRegionMeta {
        &self.metadata
    }

    fn map(&self, root_pt: PageTable, overwrite: bool) -> Vec<HeapFrameTracker> {
        todo!()
    }

    fn unmap(&self, root_pt: PageTable) {
        todo!()
    }

    fn resize(&mut self, new_pages: usize) {
        todo!()
    }

    fn fork(&mut self, parent_pt: PageTable) -> Box<dyn ASRegion> {
        todo!()
    }

    fn fault_handler(&mut self, _root_pt: PageTable, vpn: VirtPageNum) -> SyscallResult {
        todo!()
    }
}
