pub mod direct;

use alloc::boxed::Box;
use alloc::vec::Vec;
use common::arch::VirtPageNum;
use crate::kobject::KObject;
use crate::mm::page_table::PageTable;
use crate::result::MosResult;
use crate::mm::vmo::direct::VMObjectDirect;

pub trait VMObject : KObject {
    fn len(&self) -> usize;
    fn read(&self, offset: usize, buf: &mut [u8]) -> MosResult;
    fn write(&mut self, offset: usize, buf: &[u8]) -> MosResult;
    fn map(&self, pt: PageTable, vpn: VirtPageNum) -> MosResult<Vec<VMObjectDirect>>;
    fn unmap(&self, pt: PageTable, vpn: VirtPageNum) -> MosResult;
}

pub trait CopyableVMObject : VMObject {
    fn copy(&self) -> MosResult<Box<dyn VMObject>>;
}
