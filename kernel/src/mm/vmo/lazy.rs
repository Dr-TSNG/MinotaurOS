use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use log::trace;
use crate::arch::{PageTableEntry, PhysPageNum, PTEFlags, VirtAddr, VirtPageNum};
use crate::mm::addr_space::ASPerms;
use crate::mm::allocator::{alloc_user_frames, UserFrameTracker};
use crate::mm::page_table::{PageTable, SlotType};
use crate::mm::vmo::direct::VMObjectDirect;
use crate::mm::vmo::{MapInfo, VMObject};
use crate::result::{MosError, MosResult};

pub struct VMObjectLazy {
    map_info: MapInfo,
    perms: ASPerms,
    pages: Vec<PageState>,
}

enum PageState {
    Free,
    Framed(UserFrameTracker),
    CopyOnWrite(Arc<UserFrameTracker>),
}

impl VMObjectLazy {
    pub fn new_free(map_info: MapInfo, perms: ASPerms) -> Self {
        assert_eq!(map_info.level, 2);
        let mut pages = vec![];
        for _ in 0..map_info.pages {
            pages.push(PageState::Free);
        }
        Self { map_info, perms, pages }
    }

    pub fn new_framed(map_info: MapInfo, perms: ASPerms) -> MosResult<Self> {
        assert_eq!(map_info.level, 2);
        let mut pages = vec![];
        for _ in 0..map_info.pages {
            let page = alloc_user_frames(1)?;
            pages.push(PageState::Framed(page));
        }
        let obj = Self { map_info, perms, pages };
        Ok(obj)
    }

    fn map_one(&self, page: &PageState, vpn: VirtPageNum) -> MosResult<Vec<VMObjectDirect>> {
        let mut pt = self.map_info.root_pt;
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
                        if self.perms.contains(ASPerms::R) { flags |= PTEFlags::R; }
                        if self.perms.contains(ASPerms::W) { flags |= PTEFlags::W; }
                        if self.perms.contains(ASPerms::X) { flags |= PTEFlags::X; }
                        (tracker.ppn, flags)
                    }
                    PageState::CopyOnWrite(ref tracker) => {
                        let mut flags = PTEFlags::V | PTEFlags::A | PTEFlags::D | PTEFlags::U;
                        if self.perms.contains(ASPerms::R) { flags |= PTEFlags::R; }
                        // No W
                        if self.perms.contains(ASPerms::X) { flags |= PTEFlags::X; }
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
                        let dir = VMObjectDirect::new_page_dir()?;
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

    fn unmap_one(&self, vpn: VirtPageNum) -> MosResult {
        let mut pt = self.map_info.root_pt;
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

impl VMObject for VMObjectLazy {
    fn set_perms(&mut self, perms: ASPerms) -> MosResult {
        todo!()
    }

    fn map(&self) -> MosResult<Vec<VMObjectDirect>> {
        let mut dirs = vec![];
        let mut vpn = self.map_info.start;
        for page in self.pages.iter() {
            dirs.extend(self.map_one(page, vpn)?);
            vpn = vpn + 1;
        }
        Ok(dirs)
    }

    fn unmap(&self) -> MosResult {
        let mut vpn = self.map_info.start;
        for _ in self.pages.iter() {
            self.unmap_one(vpn)?;
            vpn = vpn + 1;
        }
        Ok(())
    }

    fn fault_handler(&mut self, mut pt: PageTable, vpn: VirtPageNum, perform: ASPerms) -> MosResult {
        todo!()
    }
}
