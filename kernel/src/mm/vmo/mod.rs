pub mod direct;
mod physical;

use alloc::string::String;
use core::fmt::Debug;
use downcast_rs::DowncastSync;
use common::arch::VirtPageNum;
use crate::kobject::KObject;
use crate::result::MosResult;
use crate::mm::vmas::AddressSpace;

pub trait VMObject : KObject {
    fn detail(&self) -> String;
    fn read(&self, offset: usize, buf: &mut [u8]) -> MosResult;
    fn write(&mut self, offset: usize, buf: &[u8]) -> MosResult;
    fn map(&self, addrs: &mut AddressSpace, vpn: VirtPageNum) -> MosResult;
    fn unmap(&self, addrs: &mut AddressSpace, vpn: VirtPageNum) -> MosResult;
}
