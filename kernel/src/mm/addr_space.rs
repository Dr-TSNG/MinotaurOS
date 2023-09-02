use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::arch::asm;
use core::cmp::Ordering;
use bitflags::bitflags;
use downcast_rs::Downcast;
use log::trace;
use riscv::register::satp;
use spin::RwLock;
use common::arch::{PAGE_SIZE, VirtPageNum};
use common::config::KERNEL_VADDR_BASE;
use crate::board::KERNEL_HEAP_END;
use crate::impl_kobject;
use crate::kobject::{KObject, KObjectBase, KObjectType, KoID};
use crate::mm::page_table::PageTable;
use crate::mm::vmo::direct::VMObjectDirect;
use crate::mm::vmo::{CopiableVMObject, VMObject};
use crate::result::{MosError, MosResult};

bitflags! {
    pub struct ASPerms: u8 {
        const R = 1 << 0;
        const W = 1 << 1;
        const X = 1 << 2;
        const U = 1 << 3;
    }
}

pub struct ASRegion {
    /// 区域起始页号
    pub start: VirtPageNum,
    /// 区域结束页号（开区间）
    pub end: VirtPageNum,
    /// 区域权限
    pub perms: ASPerms,
    /// 区域是否可复制
    pub copyable: bool,
    /// 区域名称
    pub name: Option<String>,
    /// 区域包含的 VM 对象
    pub vmos: Vec<Box<dyn VMObject>>,
}

impl PartialEq<Self> for ASRegion {
    fn eq(&self, other: &Self) -> bool {
        self.start == other.start && self.end == other.end
    }
}

impl PartialOrd<Self> for ASRegion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.start.partial_cmp(&other.start)
    }
}

impl Eq for ASRegion {}

impl Ord for ASRegion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.start.cmp(&other.start)
    }
}

impl ASRegion {
    pub fn new(
        start: VirtPageNum,
        end: VirtPageNum,
        perms: ASPerms,
        copiable: bool,
        name: Option<String>,
    ) -> ASRegion {
        ASRegion { start, end, perms, copyable: copiable, name, vmos: Vec::new() }
    }

    pub fn copy(&self) -> MosResult<Vec<ASRegion>> {
        if !self.copyable {
            return Err(MosError::PageNoncopyable);
        }
        let mut cur: VirtPageNum = self.start;
        let mut regions = vec![];
        let mut next_copiable_region = ASRegion::new(cur, cur, self.perms, true, self.name.clone());
        for vmo in self.vmos.iter() {
            let vmo = match vmo.as_any().downcast_ref::<Box<dyn CopiableVMObject>>() {
                Some(vmo) => vmo,
                None => return Err(MosError::PageNoncopyable),
            };
            let copy = vmo.copy()?;
            let cur_next = cur + copy.len() / PAGE_SIZE;
            if copy.as_any().downcast_ref::<Box<dyn CopiableVMObject>>().is_some() {
                next_copiable_region.end = cur_next;
                next_copiable_region.vmos.push(copy);
            } else {
                regions.push(next_copiable_region);
                next_copiable_region = ASRegion::new(cur_next, cur_next, self.perms, true, self.name.clone());
                let noncopyable_region = ASRegion::new(cur, cur_next, self.perms, false, self.name.clone());
                regions.push(noncopyable_region);
            }
            cur = cur_next;
        }
        if next_copiable_region.start != next_copiable_region.end {
            regions.push(next_copiable_region);
        }
        Ok(regions)
    }
}

// static ASID_POOL: Mutex<WeakValueHashMap<ASID, AddressSpace>> = Mutex::default();

pub type ASID = u16;

pub struct AddressSpace {
    base: KObjectBase,
    pub root_pt: PageTable,
    inner: RwLock<AddressSpaceInner>,
}
impl_kobject!(KObjectType::AddressSpace, AddressSpace);

struct AddressSpaceInner {
    /// 与地址空间关联的 ASID
    asid: ASID,
    /// 地址空间中的区域
    regions: BTreeSet<ASRegion>,
    /// 该地址空间关联的页表帧
    pt_dirs: Vec<VMObjectDirect>,
}

impl AddressSpace {
    pub fn new_bare() -> MosResult<Self> {
        let root_pt_page = VMObjectDirect::zeroed(2, ASPerms::R | ASPerms::W)?;
        let root_pt = PageTable::new(root_pt_page.ppn);
        let mut inner = AddressSpaceInner {
            asid: 0,
            regions: BTreeSet::new(),
            pt_dirs: vec![],
        };
        inner.pt_dirs.push(root_pt_page);
        let mut addrs = AddressSpace {
            base: KObjectBase::default(),
            root_pt,
            inner: RwLock::new(inner),
        };
        addrs.copy_global_mappings()?;
        for region in addrs.inner.read().regions.iter() {
            trace!("AddressSpace: {:?} {:x?} - {:x?}", region.name, region.start, region.end)
        }
        Ok(addrs)
    }

    pub fn from(another: &Self) -> MosResult<AddressSpace> {
        let addrs = Self::new_bare()?;
        let mut inner = addrs.inner.write();
        let another_inner = another.inner.read();
        for region in another_inner.regions.iter() {
            for copy in region.copy()?.into_iter() {
                inner.regions.insert(copy);
            }
        }
        drop(inner);
        Ok(addrs)
    }

    pub unsafe fn activate(&self) {
        let asid = self.inner.read().asid;
        satp::set(satp::Mode::Sv39, asid as usize, self.root_pt.ppn.0);
        asm!("sfence.vma");
    }

    fn copy_global_mappings(&mut self) -> MosResult {
        let start = VirtPageNum::from(KERNEL_VADDR_BASE);
        let end = VirtPageNum::from(KERNEL_HEAP_END);
        assert_eq!(start.index(2), 0);
        assert_eq!(end.index(2), 0);
        let mut region = ASRegion::new(
            start, end,
            ASPerms::R | ASPerms::W | ASPerms::X,
            false,
            Some("Global mapping".to_string()),
        );
        let mut cur = start;
        while cur < end {
            let vmo = VMObjectDirect::new_global(1, cur, ASPerms::R | ASPerms::W | ASPerms::X);
            region.vmos.push(Box::new(vmo));
            cur = cur.step_lv1();
        }
        self.map_region(region)?;
        Ok(())
    }

    fn map_region(&mut self, region: ASRegion) -> MosResult {
        let mut inner = self.inner.write();
        let mut cur = region.start;
        for vmo in region.vmos.iter() {
            let dirs = vmo.map(self.root_pt, cur)?;
            inner.pt_dirs.extend(dirs);
            cur = cur + vmo.len() / PAGE_SIZE;
        }
        Ok(())
    }

    fn unmap_region(&mut self, start: VirtPageNum) -> MosResult {
        let mut inner = self.inner.write();
        let region = inner.regions
            .extract_if(|region| region.start == start)
            .next()
            .ok_or(MosError::PageNotMapped(start))?;
        let mut cur = region.start;
        for vmo in region.vmos.iter() {
            vmo.unmap(self.root_pt, cur)?;
            cur = cur + vmo.len() / PAGE_SIZE;
        }
        Ok(())
    }
}
