pub mod direct;
pub mod lazy;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::any::Any;
use crate::arch::VirtPageNum;
use crate::mm::addr_space::ASPerms;
use crate::mm::page_table::PageTable;
use crate::result::MosResult;
use crate::mm::vmo::direct::VMObjectDirect;

#[derive(Clone)]
pub struct MapInfo {
    /// 根页表
    pub root_pt: PageTable,
    /// 页表级别
    pub level: usize,
    /// 映射的页数（按叶子节点计算）
    pub pages: usize,
    /// 起始虚拟页号
    pub start: VirtPageNum,
}

impl MapInfo {
    pub const fn new(root_pt: PageTable, level: usize, pages: usize, start: VirtPageNum) -> Self {
        Self { root_pt, level, pages, start }
    }

    pub fn end(&self) -> VirtPageNum {
        self.start + self.pages
    }
}

pub trait VMObject: Any + Send + Sync {
    fn set_perms(&mut self, perms: ASPerms) -> MosResult;
    fn map(&self) -> MosResult<Vec<VMObjectDirect>>;
    fn unmap(&self) -> MosResult;
    fn fault_handler(&mut self, pt: PageTable, vpn: VirtPageNum, perform: ASPerms) -> MosResult {
        panic!("fault_handler not implemented: {:?} {:?} {:?}", pt, vpn, perform);
    }
}

pub trait CopyableVMObject: VMObject {
    fn copy(&self) -> MosResult<Box<dyn VMObject>>;
}
