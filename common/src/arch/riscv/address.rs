use core::{
    fmt::{self, Debug, Formatter},
    ops::{Add, Sub},
};
use core::fmt::Display;
use crate::config::{KERNEL_ADDR_OFFSET, KERNEL_VADDR_BASE};
use super::pte::PageTableEntry;

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
        assert_eq!(v.page_offset(), 0);
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
        assert_eq!(v.page_offset(), 0);
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
        PhysPageNum((self.0 - 1 + SV39_PAGE_SIZE) / SV39_PAGE_SIZE)
    }
    pub fn page_offset(&self) -> usize {
        self.0 & (SV39_PAGE_SIZE - 1)
    }
    pub fn aligned(&self) -> bool {
        self.page_offset() == 0
    }
}

impl VirtAddr {
    pub fn floor(&self) -> VirtPageNum {
        VirtPageNum(self.0 / SV39_PAGE_SIZE)
    }
    pub fn ceil(&self) -> VirtPageNum {
        VirtPageNum((self.0 - 1 + SV39_PAGE_SIZE) / SV39_PAGE_SIZE)
    }
    pub fn page_offset(&self) -> usize {
        self.0 & (SV39_PAGE_SIZE - 1)
    }
    pub fn aligned(&self) -> bool {
        self.page_offset() == 0
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
    pub fn lv0_mask(&self) -> PhysPageNum {
        PhysPageNum(self.0 & !0x2ffff)
    }
    pub fn lv1_mask(&self) -> PhysPageNum {
        PhysPageNum(self.0 & !0x1ff)
    }
    pub fn step_lv0(&self) -> PhysPageNum {
        PhysPageNum(self.0 + (1 << (SV39_VPN_BITS * 2)))
    }
    pub fn step_lv1(&self) -> PhysPageNum {
        PhysPageNum(self.0 + (1 << SV39_VPN_BITS))
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

pub trait StepByOne {
    fn step(&mut self);
}

impl StepByOne for VirtPageNum {
    fn step(&mut self) {
        self.0 += 1;
    }
}

impl StepByOne for PhysPageNum {
    fn step(&mut self) {
        self.0 += 1;
    }
}

#[derive(Copy, Clone)]
pub struct SimpleRange<T>
    where T: StepByOne + Copy + PartialEq + PartialOrd + Debug {
    l: T,
    r: T,
}

impl<T> SimpleRange<T>
    where T: StepByOne + Copy + PartialEq + PartialOrd + Debug {
    pub fn new(start: T, end: T) -> Self {
        assert!(start <= end, "start {:?} > end {:?}!", start, end);
        Self { l: start, r: end }
    }
    pub fn get_start(&self) -> T {
        self.l
    }
    pub fn get_end(&self) -> T {
        self.r
    }
}

impl<T> IntoIterator for SimpleRange<T>
    where T: StepByOne + Copy + PartialEq + PartialOrd + Debug {
    type Item = T;
    type IntoIter = SimpleRangeIterator<T>;
    fn into_iter(self) -> Self::IntoIter {
        SimpleRangeIterator::new(self.l, self.r)
    }
}

pub struct SimpleRangeIterator<T>
    where T: StepByOne + Copy + PartialEq + PartialOrd + Debug {
    current: T,
    end: T,
}

impl<T> SimpleRangeIterator<T>
    where T: StepByOne + Copy + PartialEq + PartialOrd + Debug {
    pub fn new(l: T, r: T) -> Self {
        Self { current: l, end: r }
    }
}

impl<T> Iterator for SimpleRangeIterator<T>
    where T: StepByOne + Copy + PartialEq + PartialOrd + Debug {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        if self.current == self.end {
            None
        } else {
            let t = self.current;
            self.current.step();
            Some(t)
        }
    }
}

pub type VPNRange = SimpleRange<VirtPageNum>;
