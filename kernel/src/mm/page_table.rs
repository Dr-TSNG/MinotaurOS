use common::arch::{paddr_to_kvaddr, PageTableEntry, PhysAddr, PhysPageNum, PTE_SLOTS, PTEType, VirtAddr};

#[derive(Copy, Clone, Debug)]
pub struct PageTable {
    pub ppn: PhysPageNum,
}

pub enum SlotType {
    Invalid,
    Directory(PageTable),
    Page(VirtAddr),
}

impl PageTable {
    pub const fn empty() -> Self {
        Self { ppn: PhysPageNum(0) }
    }

    pub const fn new(ppn: PhysPageNum) -> Self {
        Self { ppn }
    }

    pub fn get_pte_array(&self) -> &[PageTableEntry] {
        let ptr = paddr_to_kvaddr(PhysAddr::from(self.ppn)).0 as *const PageTableEntry;
        unsafe { core::slice::from_raw_parts(ptr, PTE_SLOTS) }
    }

    pub fn get_pte_array_mut(&self) -> &mut [PageTableEntry] {
        let ptr = paddr_to_kvaddr(PhysAddr::from(self.ppn)).0 as *mut PageTableEntry;
        unsafe { core::slice::from_raw_parts_mut(ptr, PTE_SLOTS) }
    }

    pub fn get_pte(&self, idx: usize) -> &PageTableEntry {
        &self.get_pte_array()[idx]
    }

    pub fn get_pte_mut(&self, idx: usize) -> &mut PageTableEntry {
        &mut self.get_pte_array_mut()[idx]
    }

    pub fn slot_type(&self, idx: usize) -> SlotType {
        let pte = self.get_pte(idx);
        match pte.kind() {
            PTEType::Invalid => SlotType::Invalid,
            PTEType::Directory => SlotType::Directory(Self::new(pte.ppn())),
            PTEType::Page => {
                let addr = paddr_to_kvaddr(PhysAddr::from(pte.ppn()));
                SlotType::Page(addr)
            }
        }
    }
}
