use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::arch::asm;
use core::cmp::Ordering;
use bitflags::bitflags;
use downcast_rs::Downcast;
use log::{debug, info, trace};
use riscv::register::satp;
use xmas_elf::ElfFile;
use crate::arch::{PAGE_SIZE, PhysPageNum, PTE_SLOTS, VirtAddr, VirtPageNum};
use crate::board::GLOBAL_MAPPINGS;
use crate::config::{USER_HEAP_SIZE, USER_STACK_SIZE};
use crate::mm::page_table::PageTable;
use crate::mm::vmo::direct::VMObjectDirect;
use crate::mm::vmo::{CopyableVMObject, MapInfo, VMObject};
use crate::mm::vmo::lazy::VMObjectLazy;
use crate::process::aux::{self, Aux};
use crate::result::{MosError, MosResult};
use crate::result::MosError::InvalidExecutable;
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

    pub fn from_elf(data: &[u8]) -> MosResult<(Self, usize, usize, Vec<Aux>)> {
        let mut addrs = Self::new_bare()?;
        let elf = ElfFile::new(data).map_err(InvalidExecutable)?;
        let mut auxv: Vec<Aux> = Vec::with_capacity(64);

        let ph_count = elf.header.pt2.ph_count();

        // TODO: 动态链接
        let mut linker_base = 0;
        let mut entry_point = elf.header.pt2.entry_point() as usize;

        let mut max_end_vpn = VirtPageNum(0);
        let mut load_base = 0;
        for i in 0..ph_count {
            let phdr = elf.program_header(i).map_err(InvalidExecutable)?;
            if phdr.get_type().map_err(InvalidExecutable)? == xmas_elf::program::Type::Load {
                let start_addr = VirtAddr(phdr.virtual_addr() as usize);
                let end_addr = VirtAddr((phdr.virtual_addr() + phdr.mem_size()) as usize);
                let start_vpn = VirtPageNum::from(start_addr);
                let end_vpn = VirtPageNum::from(end_addr);
                if load_base == 0 {
                    load_base = start_addr.0;
                }

                let mut perms = ASPerms::U;
                let ph_flags = phdr.flags();
                if ph_flags.is_read() {
                    perms |= ASPerms::R;
                }
                if ph_flags.is_write() {
                    perms |= ASPerms::W;
                }
                if ph_flags.is_execute() {
                    perms |= ASPerms::X;
                }

                let map_info = MapInfo::new(
                    addrs.root_pt,
                    2,
                    (end_vpn - start_vpn).0,
                    start_vpn,
                );
                let vmo = VMObjectLazy::new_framed(map_info.clone(), perms)?;
                let region = ASRegion::new(
                    map_info,
                    perms,
                    None, // TODO: Elf name
                    Box::new(vmo),
                );
                max_end_vpn = region.map_info.end();
                addrs.map_region(region)?;
            }
        }

        // 映射用户栈
        let ustack_bottom_vpn = max_end_vpn + 1; // Guard page
        let ustack_top_vpn = ustack_bottom_vpn + USER_STACK_SIZE / PAGE_SIZE;
        let ustack_top = VirtAddr::from(ustack_top_vpn).0;
        let map_info = MapInfo::new(
            addrs.root_pt,
            2,
            (ustack_top_vpn - ustack_bottom_vpn).0,
            ustack_bottom_vpn,
        );
        let vmo = VMObjectLazy::new_free(map_info.clone(), ASPerms::U | ASPerms::R | ASPerms::W);
        let region = ASRegion::new(
            map_info,
            ASPerms::U | ASPerms::R | ASPerms::W,
            Some("[stack]".to_string()),
            Box::new(vmo),
        );
        addrs.map_region(region)?;
        info!("[from_elf] map user stack: {:?} - {:?}", ustack_bottom_vpn, ustack_top_vpn);

        // 映射用户堆
        let uheap_bottom_vpn = ustack_top_vpn + 1;
        let uheap_top_vpn = uheap_bottom_vpn + USER_HEAP_SIZE / PAGE_SIZE;
        let map_info = MapInfo::new(
            addrs.root_pt,
            2,
            (uheap_top_vpn - uheap_bottom_vpn).0,
            uheap_bottom_vpn,
        );
        let vmo = VMObjectLazy::new_free(map_info.clone(), ASPerms::U | ASPerms::R | ASPerms::W);
        let region = ASRegion::new(
            map_info,
            ASPerms::U | ASPerms::R | ASPerms::W,
            Some("[heap]".to_string()),
            Box::new(vmo),
        );
        addrs.map_region(region)?;
        info!("[from_elf] Map user heap: {:?} - {:?}", uheap_bottom_vpn, uheap_top_vpn);

        auxv.push(Aux::new(aux::AT_PHDR, load_base + elf.header.pt2.ph_offset() as usize));
        auxv.push(Aux::new(aux::AT_PHENT, elf.header.pt2.ph_entry_size() as usize));
        auxv.push(Aux::new(aux::AT_PHNUM, ph_count as usize));
        auxv.push(Aux::new(aux::AT_PAGESZ, PAGE_SIZE));
        auxv.push(Aux::new(aux::AT_BASE, linker_base));
        auxv.push(Aux::new(aux::AT_FLAGS, 0));
        auxv.push(Aux::new(aux::AT_ENTRY, elf.header.pt2.entry_point() as usize));
        auxv.push(Aux::new(aux::AT_UID, 0));
        auxv.push(Aux::new(aux::AT_EUID, 0));
        auxv.push(Aux::new(aux::AT_GID, 0));
        auxv.push(Aux::new(aux::AT_EGID, 0));

        Ok((addrs, entry_point, ustack_top, auxv))
    }

    pub unsafe fn activate(&self) {
        let asid = self.inner.read().asid;
        satp::set(satp::Mode::Sv39, asid as usize, self.root_pt.ppn.0);
        asm!("sfence.vma");
    }

    fn copy_global_mappings(&mut self) -> MosResult {
        for map in GLOBAL_MAPPINGS.iter() {
            debug!("Copy global mappings: {} from {:?} to {:?}", map.name, map.phys_start, map.phys_end());
            let ppn_start = PhysPageNum::from(map.phys_start);
            let vpn_start = VirtPageNum::from(map.virt_start);
            let vpn_end = VirtPageNum::from(map.virt_end);
            let mut cur = vpn_start;
            while cur < vpn_end {
                let next_lv1 = cur.step_lv1();
                let (level, pages, next) = match cur.index(2) == 0 && next_lv1 <= vpn_end {
                    true => (1, PTE_SLOTS, next_lv1),
                    false => (2, 1, cur + 1),
                };
                let map_info = MapInfo::new(self.root_pt, level, pages, cur);
                let ppn = ppn_start + (cur - vpn_start).0;
                let vmo = VMObjectDirect::new_global(map_info.clone(), ppn, map.perms);
                let region = ASRegion::new(
                    map_info,
                    map.perms,
                    Some(map.name.to_string()),
                    Box::new(vmo),
                );
                cur = next;
                self.map_region(region)?;
            }
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
