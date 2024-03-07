use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::arch::asm;
use bitflags::bitflags;
use log::{debug, trace};
use riscv::register::satp;
use xmas_elf::ElfFile;
use crate::arch::{paddr_to_kvaddr, PAGE_SIZE, PhysPageNum, VirtAddr, VirtPageNum};
use crate::board::{GLOBAL_MAPPINGS, PHYS_MEMORY};
use crate::config::{USER_HEAP_SIZE, USER_STACK_SIZE};
use crate::mm::allocator::{alloc_kernel_frames, HeapFrameTracker};
use crate::mm::page_table::PageTable;
use crate::mm::region::{ASRegion, ASRegionMeta};
use crate::mm::region::direct::DirectRegion;
use crate::mm::region::lazy::LazyRegion;
use crate::process::aux::{self, Aux};
use crate::result::{Errno, MosError, MosResult, SyscallResult};
use crate::result::MosError::InvalidExecutable;

bitflags! {
    pub struct ASPerms: u8 {
        const R = 1 << 0;
        const W = 1 << 1;
        const X = 1 << 2;
        const U = 1 << 3;
    }
}

// static ASID_POOL: Mutex<WeakValueHashMap<ASID, AddressSpace>> = Mutex::default();

pub type ASID = u16;

pub struct AddressSpace {
    /// 根页表
    pub root_pt: PageTable,
    /// 与地址空间关联的 ASID
    asid: ASID,
    /// 地址空间中的区域
    regions: BTreeSet<Box<dyn ASRegion>>,
    /// 该地址空间关联的页表帧
    pt_dirs: Vec<HeapFrameTracker>,
}

impl AddressSpace {
    pub fn new_bare() -> MosResult<Self> {
        let root_pt_page = alloc_kernel_frames(1)?;
        debug!("AddressSpace: create root page table {:?}", root_pt_page.ppn);
        let mut addrs = AddressSpace {
            root_pt: PageTable::new(root_pt_page.ppn),
            asid: 0,
            regions: BTreeSet::new(),
            pt_dirs: vec![],
        };
        addrs.pt_dirs.push(root_pt_page);
        addrs.copy_global_mappings()?;
        for region in addrs.regions.iter() {
            let start = region.metadata().start;
            let end = start + region.metadata().pages;
            trace!("AddressSpace: {:?} {:x?} - {:x?}", region.metadata().name, start, end)
        }
        Ok(addrs)
    }

    pub fn from(another: &Self) -> MosResult<AddressSpace> {
        let mut addrs = Self::new_bare()?;
        for region in another.regions.iter() {
            addrs.regions.insert(region.copy()?);
        }
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
                let end_vpn = end_addr.ceil();
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
                let buf = &elf
                    .input[phdr.offset() as usize..(phdr.offset() + phdr.file_size()) as usize];
                let region = LazyRegion::new_framed(
                    ASRegionMeta {
                        name: None,
                        perms,
                        start: start_vpn,
                        pages: (end_vpn - start_vpn).0,
                    },
                    Some(buf),
                )?;
                max_end_vpn = region.metadata().end();
                addrs.map_region(region)?;
                debug!("Map elf section: {:?} - {:?}", start_vpn, end_vpn);
            }
        }

        // 映射用户栈
        let ustack_bottom_vpn = max_end_vpn + 1; // Guard page
        let ustack_top_vpn = ustack_bottom_vpn + USER_STACK_SIZE / PAGE_SIZE;
        let ustack_top = VirtAddr::from(ustack_top_vpn).0;
        let region = LazyRegion::new_free(ASRegionMeta {
            name: Some("[stack]".to_string()),
            perms: ASPerms::U | ASPerms::R | ASPerms::W,
            start: ustack_bottom_vpn,
            pages: (ustack_top_vpn - ustack_bottom_vpn).0,
        });
        addrs.map_region(region)?;
        debug!("Map user stack: {:?} - {:?}", ustack_bottom_vpn, ustack_top_vpn);

        // 映射用户堆
        let uheap_bottom_vpn = ustack_top_vpn + 1;
        let uheap_top_vpn = uheap_bottom_vpn + USER_HEAP_SIZE / PAGE_SIZE;
        let region = LazyRegion::new_free(ASRegionMeta {
            name: Some("[heap]".to_string()),
            perms: ASPerms::U | ASPerms::R | ASPerms::W,
            start: uheap_bottom_vpn,
            pages: (uheap_top_vpn - uheap_bottom_vpn).0,
        });
        addrs.map_region(region)?;
        debug!("Map user heap: {:?} - {:?}", uheap_bottom_vpn, uheap_top_vpn);

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
        satp::set(satp::Mode::Sv39, self.asid as usize, self.root_pt.ppn.0);
        asm!("sfence.vma");
    }

    fn copy_global_mappings(&mut self) -> MosResult {
        for map in GLOBAL_MAPPINGS.iter() {
            debug!("Copy global mappings: {} from {:?} to {:?}", map.name, map.phys_start, map.phys_end());
            let ppn_start = PhysPageNum::from(map.phys_start);
            let vpn_start = VirtPageNum::from(map.virt_start);
            let vpn_end = VirtPageNum::from(map.virt_end);

            let metadata = ASRegionMeta {
                name: Some(map.name.to_string()),
                perms: map.perms,
                start: vpn_start,
                pages: (vpn_end - vpn_start).0,
            };
            let region = DirectRegion::new(metadata, ppn_start);
            self.map_region(region)?;
        }
        for (paddr_start, paddr_end) in PHYS_MEMORY.iter() {
            debug!("Copy global mappings: [physical] from {:?} to {:?}", paddr_start, paddr_end);
            let ppn_start = PhysPageNum::from(*paddr_start);
            let vpn_start = VirtPageNum::from(paddr_to_kvaddr(*paddr_start));
            let vpn_end = VirtPageNum::from(paddr_to_kvaddr(*paddr_end));
            
            let metadata = ASRegionMeta {
                name: Some("[physical]".to_string()),
                perms: ASPerms::R | ASPerms::W,
                start: vpn_start,
                pages: (vpn_end - vpn_start).0,
            };
            let region = DirectRegion::new(metadata, ppn_start);
            self.map_region(region)?;
        }
        Ok(())
    }

    pub fn map_region(&mut self, region: Box<dyn ASRegion>) -> MosResult {
        let dirs = region.map(self.root_pt)?;
        self.regions.insert(region);
        self.pt_dirs.extend(dirs);
        Ok(())
    }

    pub fn unmap_region(&mut self, start: VirtPageNum) -> MosResult<Box<dyn ASRegion>> {
        let region = self.regions
            .extract_if(|region| region.metadata().start == start)
            .next()
            .ok_or(MosError::BadAddress(VirtAddr::from(start)))?;
        region.unmap(self.root_pt)?;
        Ok(region)
    }
    
    pub fn handle_page_fault(&mut self, addr: VirtAddr, perform: ASPerms) -> MosResult {
        let vpn = addr.floor();
        let mut region = self.regions
            .extract_if(|region| region.metadata().start <= vpn && region.metadata().end() > vpn)
            .next()
            .ok_or(MosError::BadAddress(addr))?;
        
        let result = if region.metadata().perms.contains(perform) {
            region.fault_handler(self.root_pt, vpn)
        } else {
            Err(MosError::PageAccessDenied(addr.into()))
        };
        self.regions.insert(region);
        result
    }

    pub fn check_addr_valid(&self, start: VirtAddr, end: VirtAddr, perms: ASPerms) -> SyscallResult<()> {
        let vpn_start = start.floor();
        let vpn_end = end.floor();
        let mut cur = vpn_start;
        for region in self.regions.iter() {
            let metadata = region.metadata();
            if metadata.start > cur {
                return Err(Errno::EFAULT);
            } else if cur < metadata.end() {
                if metadata.perms.contains(perms) {
                    cur = metadata.end();
                    if cur >= vpn_end {
                        return Ok(());
                    }
                } else {
                    return Err(Errno::EACCES);
                }
            }
        }
        Err(Errno::EFAULT)
    }

    pub fn user_slice_r(&self, addr: VirtAddr, len: usize) -> SyscallResult<&'static [u8]> {
        self.check_addr_valid(addr, addr + len, ASPerms::R | ASPerms::U)?;
        let data = unsafe { core::slice::from_raw_parts(addr.as_ptr(), len) };
        Ok(data)
    }

    pub fn user_slice_w(&self, addr: VirtAddr, len: usize) -> SyscallResult<&'static mut [u8]> {
        self.check_addr_valid(addr, addr + len, ASPerms::W | ASPerms::U)?;
        let data = unsafe { core::slice::from_raw_parts_mut(addr.as_ptr(), len) };
        Ok(data)
    }

    pub fn user_slice_rw(&self, addr: VirtAddr, len: usize) -> SyscallResult<&'static mut [u8]> {
        self.check_addr_valid(addr, addr + len, ASPerms::R | ASPerms::W | ASPerms::U)?;
        let data = unsafe { core::slice::from_raw_parts_mut(addr.as_ptr(), len) };
        Ok(data)
    }
}
