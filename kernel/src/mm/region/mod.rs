pub mod direct;
pub mod file;
pub mod lazy;
pub mod shared;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
use crate::arch::VirtPageNum;
use crate::mm::addr_space::ASPerms;
use crate::mm::allocator::HeapFrameTracker;
use crate::mm::page_table::PageTable;
use crate::result::{Errno, SyscallResult};

/// 地址空间区域
///
/// 此区域仅对一个地址空间有意义
#[allow(unused)]
pub trait ASRegion: Send + Sync {
    fn metadata(&self) -> &ASRegionMeta;

    fn metadata_mut(&mut self) -> &mut ASRegionMeta;

    /// 将区域映射到页表，返回创建的页表帧
    fn map(&self, root_pt: PageTable, overwrite: bool) -> Vec<HeapFrameTracker>;

    /// 将区域取消映射到页表
    fn unmap(&self, root_pt: PageTable);

    /// 分割区域
    fn split(&mut self, start: usize, size: usize) -> Vec<Box<dyn ASRegion>>;

    /// 扩展区域
    fn extend(&mut self, size: usize);

    /// 拷贝区域
    fn fork(&mut self, parent_pt: PageTable) -> Box<dyn ASRegion>;

    /// 同步区域
    fn sync(&self) {}

    /// 错误处理
    fn fault_handler(&mut self, root_pt: PageTable, vpn: VirtPageNum) -> SyscallResult<Vec<HeapFrameTracker>> {
        Err(Errno::EINVAL)
    }
}

impl dyn ASRegion {
    /// 设置区域的权限
    ///
    /// SAFETY: 需要手动调用 `map` 或 `unmap` 来更新页表
    pub fn set_perms(&mut self, perms: ASPerms) {
        let s_perms = &mut self.metadata_mut().perms;
        *s_perms = (*s_perms - ASPerms::RWX) | (perms & ASPerms::RWX);
    }
}

#[derive(Clone)]
pub struct ASRegionMeta {
    /// 区域名
    pub name: Option<String>,
    /// 区域的权限
    ///
    /// 此权限对于用户可见，但不一定和页表中的权限相同
    pub perms: ASPerms,
    /// 起始虚拟页号
    pub start: VirtPageNum,
    /// 映射的页数
    pub pages: usize,
    pub offset: usize,
    pub dev: u64,
    pub ino: usize,
}

impl ASRegionMeta {
    pub fn end(&self) -> VirtPageNum {
        self.start + self.pages
    }
}

impl PartialEq<Self> for dyn ASRegion {
    fn eq(&self, other: &Self) -> bool {
        self.metadata().start == other.metadata().start && self.metadata().pages == other.metadata().pages
    }
}

impl PartialOrd<Self> for dyn ASRegion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.metadata().start.partial_cmp(&other.metadata().start)
    }
}

impl Eq for dyn ASRegion {}

impl Ord for dyn ASRegion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.metadata().start.cmp(&other.metadata().start)
    }
}
