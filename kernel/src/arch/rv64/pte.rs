use bitflags::*;
use super::address::PhysPageNum;

bitflags! {
    #[derive(Eq, PartialEq)]
    pub struct PTEFlags: u8 {
        const V = 1 << 0;
        const R = 1 << 1;
        const W = 1 << 2;
        const X = 1 << 3;
        const U = 1 << 4;
        const G = 1 << 5;
        const A = 1 << 6;
        const D = 1 << 7;
    }
}

pub const PTE_SLOTS: usize = 512;

pub enum PTEType {
    Invalid,
    Directory,
    Page,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct PageTableEntry {
    pub bits: usize,
}

impl PageTableEntry {
    pub fn new(ppn: PhysPageNum, flags: PTEFlags) -> Self {
        PageTableEntry {
            bits: ppn.0 << 10 | flags.bits() as usize,
        }
    }
    pub fn ppn(&self) -> PhysPageNum {
        PhysPageNum(self.bits >> 10 & ((1usize << 44) - 1))
    }
    pub fn flags(&self) -> PTEFlags {
        PTEFlags::from_bits(self.bits as u8).unwrap()
    }
    pub fn valid(&self) -> bool {
        self.flags().contains(PTEFlags::V)
    }
    pub fn kind(&self) -> PTEType {
        let flags = self.flags();
        if !flags.contains(PTEFlags::V) {
            PTEType::Invalid
        } else if flags & (PTEFlags::R | PTEFlags::W | PTEFlags::X) == PTEFlags::empty() {
            PTEType::Directory
        } else {
            PTEType::Page
        }
    }
    pub fn set_flags(&mut self, flags: PTEFlags) {
        self.bits -= self.bits % (1 << 8);
        self.bits |= flags.bits() as usize;
    }
}
