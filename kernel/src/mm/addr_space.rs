use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::arch::asm;
use core::cmp::Ordering;
use bitflags::bitflags;
use downcast_rs::Downcast;
use log::{debug, trace};
use riscv::register::satp;
use crate::arch::{kvpn_to_ppn, PhysPageNum, PTE_SLOTS, VirtAddr, VirtPageNum};
use crate::board::CONSOLE_PADDR_BASE;
use crate::config::{CONSOLE_VADDR_BASE, KERNEL_VADDR_BASE, LINKAGE_EKERNEL};
use crate::debug::console;
use crate::mm::page_table::PageTable;
use crate::mm::vmo::direct::VMObjectDirect;
use crate::mm::vmo::{CopyableVMObject, MapInfo, VMObject};
use crate::result::{MosError, MosResult};
use crate::sync::mutex::RwLock;

bitflags! {
    pub struct ASPerms: u8 {
        const R = 1 << 0;
        const W = 1 << 1;
        const X = 1 << 2;
        const U = 1 << 3;
    }
}

pub struct ASRegion {
    /// 区域映射信息
    pub map_info: MapInfo,
    /// 区域权限
    pub perms: ASPerms,
    /// 区域名称
    pub name: Option<String>,
    /// 区域的 VM 实现
    pub vmo: Box<dyn VMObject>,
}

impl PartialEq<Self> for ASRegion {
    fn eq(&self, other: &Self) -> bool {
        self.map_info.start == other.map_info.start && self.map_info.pages == other.map_info.pages
    }
}

impl PartialOrd<Self> for ASRegion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.map_info.start.partial_cmp(&other.map_info.start)
    }
}

impl Eq for ASRegion {}

impl Ord for ASRegion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.map_info.start.cmp(&other.map_info.start)
    }
}

impl ASRegion {
    pub fn new(
        map_info: MapInfo,
        perms: ASPerms,
        name: Option<String>,
        vmo: Box<dyn VMObject>,
    ) -> ASRegion {
        ASRegion { map_info, perms, name, vmo }
    }

    pub fn copy(&self) -> MosResult<ASRegion> {
        let vmo = match self.vmo.as_any().downcast_ref::<Box<dyn CopyableVMObject>>() {
            Some(vmo) => vmo,
            None => return Err(MosError::PageNoncopyable),
        };
        let copy = vmo.copy()?;
        let region = ASRegion::new(
            self.map_info.clone(),
            self.perms,
            self.name.clone(),
            copy,
        );
        Ok(region)
    }
}

// static ASID_POOL: Mutex<WeakValueHashMap<ASID, AddressSpace>> = Mutex::default();

pub type ASID = u16;

pub struct AddressSpace {
    pub root_pt: PageTable,
    inner: RwLock<AddressSpaceInner>,
}

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
        let root_pt_page = VMObjectDirect::new_page_dir()?;
        debug!("AddressSpace: create root page table {:?}", root_pt_page.ppn);
        let root_pt = PageTable::new(root_pt_page.ppn);
        let mut inner = AddressSpaceInner {
            asid: 0,
            regions: BTreeSet::new(),
            pt_dirs: vec![],
        };
        inner.pt_dirs.push(root_pt_page);
        let mut addrs = AddressSpace {
            root_pt,
            inner: RwLock::new(inner),
        };
        addrs.copy_global_mappings()?;
        for region in addrs.inner.read().regions.iter() {
            let start = region.map_info.start;
            let end = start + region.map_info.pages;
            trace!("AddressSpace: {:?} {:x?} - {:x?}", region.name, start, end)
        }
        Ok(addrs)
    }

    pub fn from(another: &Self) -> MosResult<AddressSpace> {
        let addrs = Self::new_bare()?;
        let mut inner = addrs.inner.write();
        let another_inner = another.inner.read();
        for region in another_inner.regions.iter() {
            inner.regions.insert(region.copy()?);
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
        let end = VirtPageNum::from(*LINKAGE_EKERNEL);
        assert_eq!(start.index(2), 0);
        assert_eq!(end.index(2), 0);
        let mut cur = start;
        while cur < end {
            let next = cur.step_lv1();
            let map_info = MapInfo::new(self.root_pt, 1, PTE_SLOTS, cur);
            let ppn = kvpn_to_ppn(cur);
            let perms = ASPerms::R | ASPerms::W | ASPerms::X;
            let vmo = VMObjectDirect::new_global(map_info.clone(), ppn, perms);
            let region = ASRegion::new(
                map_info,
                perms,
                Some("Global lv1 mapping".to_string()),
                Box::new(vmo),
            );
            cur = next;
            self.map_region(region)?;
        }
        if let Some(base) = CONSOLE_PADDR_BASE {
            let map_info = MapInfo::new(self.root_pt, 2, 1, VirtPageNum::from(CONSOLE_VADDR_BASE));
            let ppn = PhysPageNum::from(base);
            let perms = ASPerms::R | ASPerms::W;
            let vmo = VMObjectDirect::new_global(map_info.clone(), ppn, perms);
            let region = ASRegion::new(
                map_info,
                ASPerms::R | ASPerms::W,
                Some("Main tty MMIO".to_string()),
                Box::new(vmo),
            );
            self.map_region(region)?;
            console::try_init_late();
        }
        Ok(())
    }

    pub fn map_region(&mut self, region: ASRegion) -> MosResult {
        let dirs = region.vmo.map()?;
        let mut inner = self.inner.write();
        inner.regions.insert(region);
        inner.pt_dirs.extend(dirs);
        Ok(())
    }

    pub fn unmap_region(&mut self, start: VirtPageNum) -> MosResult<ASRegion> {
        let mut inner = self.inner.write();
        let region = inner.regions
            .extract_if(|region| region.map_info.start == start)
            .next()
            .ok_or(MosError::BadAddress(VirtAddr::from(start)))?;
        region.vmo.unmap()?;
        Ok(region)
    }
}
