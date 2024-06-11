use crate::arch::{
    paddr_to_kvaddr, PTEType, PageTableEntry, PhysAddr, PhysPageNum, VirtAddr, VirtPageNum,
    PTE_SLOTS,
};

#[derive(Copy, Clone, Debug)]
pub struct PageTable {
    pub ppn: PhysPageNum,
}

pub enum SlotType {
    Invalid,
    Directory(PageTable),
    Page(PhysPageNum),
}

impl PageTable {
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
            PTEType::Page => SlotType::Page(pte.ppn()),
        }
    }

    pub fn translate(&self, vaddr: VirtAddr) -> PhysAddr {
        let mut pt = *self;
        let vpn = VirtPageNum::from(vaddr.floor());
        for (i, idx) in vpn.indexes().iter().enumerate() {
            match pt.slot_type(*idx) {
                SlotType::Invalid => panic!("Page table translate failed"),
                SlotType::Directory(next) => pt = next,
                SlotType::Page(ppn) => return PhysAddr::from(ppn) + vaddr.page_offset(i),
            }
        }
        panic!("Should not reach here")
    }
}
