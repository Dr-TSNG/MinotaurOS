pub mod direct;
pub mod lazy;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
use crate::arch::VirtPageNum;
use crate::mm::addr_space::ASPerms;
use crate::mm::allocator::HeapFrameTracker;
use crate::mm::page_table::PageTable;
use crate::result::{MosError, MosResult};

/// 地址空间区域
///
/// 此区域仅对一个地址空间有意义
pub trait ASRegion: Send + Sync {
    fn metadata(&self) -> &ASRegionMeta;

    /// 将区域映射到页表，返回创建的页表帧
    fn map(&self, root_pt: PageTable, overwrite: bool) -> MosResult<Vec<HeapFrameTracker>>;

    /// 将区域取消映射到页表
    fn unmap(&self, root_pt: PageTable) -> MosResult;

    /// 调整区域大小
    /// 
    /// SAFETY: 需要手动调用 `map` 或 `unmap` 来更新页表
    fn resize(&mut self, new_pages: usize);

    /// 拷贝区域
    fn fork(&mut self, parent_pt: PageTable) -> MosResult<Box<dyn ASRegion>>;

    /// 错误处理
    fn fault_handler(&mut self, _root_pt: PageTable, vpn: VirtPageNum) -> MosResult {
        Err(MosError::PageAccessDenied(vpn.into()))
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
