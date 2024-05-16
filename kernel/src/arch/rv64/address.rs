use core::{
    fmt::{self, Debug, Formatter},
    ops::{Add, Sub},
};
use core::iter::Step;
use crate::config::KERNEL_ADDR_OFFSET;

pub const SV39_PAGE_BITS: usize = 12;
pub const SV39_PAGE_SIZE: usize = 4096;
pub const SV39_PA_WIDTH: usize = 56;
pub const SV39_PPN_WIDTH: usize = SV39_PA_WIDTH - SV39_PAGE_BITS;
pub const SV39_VPN_BITS: usize = 9;
pub const SV39_VPN_MASK: usize = 0x1FF;

/// Definitions
#[repr(C)]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct PhysAddr(pub usize);

#[repr(C)]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct PhysPageNum(pub usize);

#[repr(C)]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct VirtAddr(pub usize);

#[repr(C)]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct VirtPageNum(pub usize);

/// Debugging

impl Debug for PhysAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("PA({:#x})", self.0))
    }
}

impl Debug for PhysPageNum {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("PPN({:#x})", self.0))
    }
}

impl Debug for VirtAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("VA({:#x})", self.0))
    }
}

impl Debug for VirtPageNum {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("VPN({:#x})", self.0))
    }
}

// Transforms

impl const From<usize> for PhysAddr {
    fn from(v: usize) -> Self {
        Self(v & ((1 << SV39_PA_WIDTH) - 1))
    }
}

impl const From<usize> for PhysPageNum {
    fn from(v: usize) -> Self {
        Self(v & ((1 << SV39_PPN_WIDTH) - 1))
    }
}

impl const From<usize> for VirtAddr {
    fn from(v: usize) -> Self {
        Self(v)
    }
}

impl const From<usize> for VirtPageNum {
    fn from(v: usize) -> Self {
        Self(v)
    }
}

impl const From<PhysAddr> for PhysPageNum {
    fn from(v: PhysAddr) -> Self {
        assert!(v.aligned(2));
        v.floor()
    }
}

impl const From<PhysPageNum> for PhysAddr {
    fn from(v: PhysPageNum) -> Self {
        Self(v.0 << SV39_PAGE_BITS)
    }
}

impl const From<VirtAddr> for VirtPageNum {
    fn from(v: VirtAddr) -> Self {
        assert!(v.aligned(2));
        v.floor()
    }
}

impl const From<VirtPageNum> for VirtAddr {
    fn from(v: VirtPageNum) -> Self {
        Self(v.0 << SV39_PAGE_BITS)
    }
}

pub const fn paddr_to_kvaddr(paddr: PhysAddr) -> VirtAddr {
    VirtAddr(paddr.0 + KERNEL_ADDR_OFFSET)
}

pub const fn kvaddr_to_paddr(vaddr: VirtAddr) -> PhysAddr {
    PhysAddr(vaddr.0 - KERNEL_ADDR_OFFSET)
}

pub const fn ppn_to_kvpn(ppn: PhysPageNum) -> VirtPageNum {
    VirtPageNum(ppn.0 + KERNEL_ADDR_OFFSET / SV39_PAGE_SIZE)
}

pub const fn kvpn_to_ppn(kvpn: VirtPageNum) -> PhysPageNum {
    PhysPageNum(kvpn.0 - KERNEL_ADDR_OFFSET / SV39_PAGE_SIZE)
}

// Operations

impl PhysAddr {
    pub fn floor(&self) -> PhysPageNum {
        PhysPageNum(self.0 / SV39_PAGE_SIZE)
    }
    pub fn ceil(&self) -> PhysPageNum {
        PhysPageNum(self.0.div_ceil(SV39_PAGE_SIZE))
    }
    pub fn page_offset(&self, level: usize) -> usize {
        self.0 & ((1 << (SV39_PAGE_BITS + SV39_VPN_BITS * (2 - level))) - 1)
    }
    pub fn aligned(&self, level: usize) -> bool {
        self.page_offset(level) == 0
    }
}

impl VirtAddr {
    pub fn floor(&self) -> VirtPageNum {
        VirtPageNum(self.0 / SV39_PAGE_SIZE)
    }
    pub fn ceil(&self) -> VirtPageNum {
        VirtPageNum(self.0.div_ceil(SV39_PAGE_SIZE))
    }
    pub fn page_offset(&self, level: usize) -> usize {
        self.0 & ((1 << (SV39_PAGE_BITS + SV39_VPN_BITS * (2 - level))) - 1)
    }
    pub fn aligned(&self, level: usize) -> bool {
        self.page_offset(level) == 0
    }
    pub fn as_ptr(&self) -> *mut u8 {
        self.0 as *mut u8
    }
}

//           |<---------  26  --------->|<-- 9 -->|<-- 9 -->|<--  12  -->|
// PhysAddr: |--------------------------|---------|---------|------------|
//      PPN: |           lv0            |   lv1   |   lv2   |
//
//           |<-- 9 -->|<-- 9 -->|<-- 9 -->|<--  12  -->|
// VirtAddr: |---------|---------|---------|------------|
//      VPN: |   lv0   |   lv1   |   lv2   |

impl PhysPageNum {
    pub fn byte_array(&self) -> &'static mut [u8] {
        unsafe {
            let vaddr = VirtAddr::from(ppn_to_kvpn(*self)).as_ptr();
            core::slice::from_raw_parts_mut(vaddr, SV39_PAGE_SIZE)
        }
    }
}

impl VirtPageNum {
    pub const fn index(&self, level: usize) -> usize {
        assert!(level < 3);
        (self.0 >> (SV39_VPN_BITS * (2 - level))) & SV39_VPN_MASK
    }
    pub fn indexes(&self) -> [usize; 3] {
        let mut vpn = self.0;
        let mut idx = [0usize; 3];
        for i in (0..3).rev() {
            idx[i] = vpn & SV39_VPN_MASK;
            vpn >>= SV39_VPN_BITS;
        }
        idx
    }
    pub fn step_lv0(&self) -> VirtPageNum {
        VirtPageNum(self.0 + (1 << (SV39_VPN_BITS * 2)))
    }
    pub fn step_lv1(&self) -> VirtPageNum {
        VirtPageNum(self.0 + (1 << SV39_VPN_BITS))
    }
}

impl const Add for PhysAddr {
    type Output = PhysAddr;
    fn add(self, rhs: Self) -> Self::Output {
        PhysAddr(self.0 + rhs.0)
    }
}

impl const Add<usize> for PhysAddr {
    type Output = PhysAddr;
    fn add(self, rhs: usize) -> Self::Output {
        PhysAddr(self.0 + rhs)
    }
}

impl const Sub for PhysAddr {
    type Output = PhysAddr;
    fn sub(self, rhs: Self) -> Self::Output {
        PhysAddr(self.0 - rhs.0)
    }
}

impl const Sub<usize> for PhysAddr {
    type Output = PhysAddr;
    fn sub(self, rhs: usize) -> Self::Output {
        PhysAddr(self.0 - rhs)
    }
}

impl const Step for PhysAddr {
    fn steps_between(start: &Self, end: &Self) -> Option<usize> {
        Some(end.0 - start.0)
    }

    fn forward_checked(start: Self, count: usize) -> Option<Self> {
        start.0.checked_add(count).map(PhysAddr)
    }

    fn backward_checked(start: Self, count: usize) -> Option<Self> {
        start.0.checked_sub(count).map(PhysAddr)
    }
}

impl const Add for PhysPageNum {
    type Output = PhysPageNum;
    fn add(self, rhs: Self) -> Self::Output {
        PhysPageNum(self.0 + rhs.0)
    }
}

impl const Add<usize> for PhysPageNum {
    type Output = PhysPageNum;
    fn add(self, rhs: usize) -> Self::Output {
        PhysPageNum(self.0 + rhs)
    }
}

impl const Sub for PhysPageNum {
    type Output = PhysPageNum;
    fn sub(self, rhs: Self) -> Self::Output {
        PhysPageNum(self.0 - rhs.0)
    }
}

impl const Sub<usize> for PhysPageNum {
    type Output = PhysPageNum;
    fn sub(self, rhs: usize) -> Self::Output {
        PhysPageNum(self.0 - rhs)
    }
}

impl const Step for PhysPageNum {
    fn steps_between(start: &Self, end: &Self) -> Option<usize> {
        Some(end.0 - start.0)
    }

    fn forward_checked(start: Self, count: usize) -> Option<Self> {
        start.0.checked_add(count).map(PhysPageNum)
    }

    fn backward_checked(start: Self, count: usize) -> Option<Self> {
        start.0.checked_sub(count).map(PhysPageNum)
    }
}

impl const Add for VirtAddr {
    type Output = VirtAddr;
    fn add(self, rhs: Self) -> Self::Output {
        VirtAddr(self.0 + rhs.0)
    }
}

impl const Add<usize> for VirtAddr {
    type Output = VirtAddr;
    fn add(self, rhs: usize) -> Self::Output {
        VirtAddr(self.0 + rhs)
    }
}

impl const Sub for VirtAddr {
    type Output = VirtAddr;
    fn sub(self, rhs: Self) -> Self::Output {
        VirtAddr(self.0 - rhs.0)
    }
}

impl const Sub<usize> for VirtAddr {
    type Output = VirtAddr;
    fn sub(self, rhs: usize) -> Self::Output {
        VirtAddr(self.0 - rhs)
    }
}

impl const Step for VirtAddr {
    fn steps_between(start: &Self, end: &Self) -> Option<usize> {
        Some(end.0 - start.0)
    }

    fn forward_checked(start: Self, count: usize) -> Option<Self> {
        start.0.checked_add(count).map(VirtAddr)
    }

    fn backward_checked(start: Self, count: usize) -> Option<Self> {
        start.0.checked_sub(count).map(VirtAddr)
    }
}

impl const Add for VirtPageNum {
    type Output = VirtPageNum;
    fn add(self, rhs: Self) -> Self::Output {
        VirtPageNum(self.0 + rhs.0)
    }
}

impl const Add<usize> for VirtPageNum {
    type Output = VirtPageNum;
    fn add(self, rhs: usize) -> Self::Output {
        VirtPageNum(self.0 + rhs)
    }
}

impl const Sub for VirtPageNum {
    type Output = VirtPageNum;
    fn sub(self, rhs: Self) -> Self::Output {
        VirtPageNum(self.0 - rhs.0)
    }
}

impl const Sub<usize> for VirtPageNum {
    type Output = VirtPageNum;
    fn sub(self, rhs: usize) -> Self::Output {
        VirtPageNum(self.0 - rhs)
    }
}

impl const Step for VirtPageNum {
    fn steps_between(start: &Self, end: &Self) -> Option<usize> {
        Some(end.0 - start.0)
    }

    fn forward_checked(start: Self, count: usize) -> Option<Self> {
        start.0.checked_add(count).map(VirtPageNum)
    }

    fn backward_checked(start: Self, count: usize) -> Option<Self> {
        start.0.checked_sub(count).map(VirtPageNum)
    }
}
