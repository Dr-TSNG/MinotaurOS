use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::arch::asm;
use core::cmp::min;
use core::ffi::CStr;
use bitflags::bitflags;
use log::{debug, info, warn};
use riscv::register::satp;
use xmas_elf::ElfFile;
use crate::arch::{PAGE_SIZE, PhysPageNum, VirtAddr, VirtPageNum};
use crate::config::{DYNAMIC_LINKER_BASE, TRAMPOLINE_BASE, USER_HEAP_SIZE, USER_STACK_SIZE, USER_STACK_TOP};
use crate::driver::GLOBAL_MAPPINGS;
use crate::fs::file_system::MountNamespace;
use crate::fs::inode::Inode;
use crate::mm::allocator::{alloc_kernel_frames, HeapFrameTracker};
use crate::mm::page_table::PageTable;
use crate::mm::region::{ASRegion, ASRegionMeta};
use crate::mm::region::direct::DirectRegion;
use crate::mm::region::file::FileRegion;
use crate::mm::region::lazy::LazyRegion;
use crate::process::aux::{self, Aux};
use crate::result::{Errno, SyscallResult};

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
    regions: BTreeMap<VirtPageNum, Box<dyn ASRegion>>,
    /// 该地址空间关联的页表帧
    pt_dirs: Vec<HeapFrameTracker>,
    /// 当前 brk 指针
    brk: VirtAddr,
}

impl AddressSpace {
    pub fn new_bare() -> Self {
        let root_pt_page = alloc_kernel_frames(1);
        debug!("AddressSpace: create root page table {:?}", root_pt_page.ppn);
        let mut addr_space = AddressSpace {
            root_pt: PageTable::new(root_pt_page.ppn),
            asid: 0,
            regions: BTreeMap::new(),
            pt_dirs: vec![],
            brk: VirtAddr(0),
        };
        addr_space.pt_dirs.push(root_pt_page);
        addr_space
    }

    pub fn new_kernel() -> Self {
        let mut addr_space = Self::new_bare();
        addr_space.copy_global_mappings();
        for region in addr_space.regions.values() {
            let start = region.metadata().start;
            let end = start + region.metadata().pages;
            info!("AddressSpace: {:?} {:x?} - {:x?}", region.metadata().name, start, end)
        }
        addr_space
    }

    pub async fn from_elf(
        mnt_ns: &MountNamespace,
        data: &[u8],
    ) -> SyscallResult<(Self, usize, Vec<Aux>)> {
        let mut addr_space = Self::new_bare();
        addr_space.copy_global_mappings();
        addr_space.map_trampoline()?;
        let elf = ElfFile::new(data).map_err(|_| Errno::ENOEXEC)?;
        let ph_count = elf.header.pt2.ph_count();

        let mut entry = elf.header.pt2.entry_point() as usize;
        let mut load_base = 0;
        let mut linker_base = 0;
        let mut max_end_vpn = VirtPageNum(0);
        for i in 0..ph_count {
            let phdr = elf.program_header(i).map_err(|_| Errno::ENOEXEC)?;
            match phdr.get_type().map_err(|_| Errno::ENOEXEC)? {
                xmas_elf::program::Type::Load => {
                    let start_addr = VirtAddr(phdr.virtual_addr() as usize);
                    let end_addr = VirtAddr((phdr.virtual_addr() + phdr.mem_size()) as usize);
                    let start_vpn = start_addr.floor();
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
                        buf,
                        start_addr.page_offset(2),
                    )?;
                    max_end_vpn = region.metadata().end();
                    addr_space.map_region(region);
                    debug!("Map elf section: {:?} - {:?}", start_vpn, end_vpn);
                }
                xmas_elf::program::Type::Interp => {
                    linker_base = DYNAMIC_LINKER_BASE;
                    entry = addr_space.load_linker(mnt_ns, linker_base).await?;
                }
                _ => {}
            }
        }

        // 映射用户栈
        let ustack_top_vpn = VirtPageNum::from(USER_STACK_TOP);
        let ustack_bottom_vpn = ustack_top_vpn - USER_STACK_SIZE / PAGE_SIZE;
        let region = LazyRegion::new_free(ASRegionMeta {
            name: Some("[stack]".to_string()),
            perms: ASPerms::U | ASPerms::R | ASPerms::W,
            start: ustack_bottom_vpn,
            pages: (ustack_top_vpn - ustack_bottom_vpn).0,
        });
        addr_space.map_region(region);
        debug!("Map user stack: {:?} - {:?}", ustack_bottom_vpn, ustack_top_vpn);

        // 映射用户堆
        let uheap_bottom_vpn = max_end_vpn;
        let uheap_top_vpn = uheap_bottom_vpn + USER_HEAP_SIZE / PAGE_SIZE;
        let region = LazyRegion::new_free(ASRegionMeta {
            name: Some("[heap]".to_string()),
            perms: ASPerms::U | ASPerms::R | ASPerms::W,
            start: uheap_bottom_vpn,
            pages: (uheap_top_vpn - uheap_bottom_vpn).0,
        });
        addr_space.map_region(region);
        addr_space.brk = VirtAddr::from(uheap_top_vpn);
        debug!("Map user heap: {:?} - {:?}", uheap_bottom_vpn, uheap_top_vpn);

        let mut auxv: Vec<Aux> = Vec::with_capacity(64);
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

        Ok((addr_space, entry, auxv))
    }

    pub fn fork(&mut self) -> AddressSpace {
        let mut forked = Self::new_bare();
        for region in self.regions.values_mut() {
            let forked_region = region.fork(self.root_pt);
            forked.map_region(forked_region);
        }
        forked
    }

    pub unsafe fn activate(&self) {
        satp::set(satp::Mode::Sv39, self.asid as usize, self.root_pt.ppn.0);
        asm!("sfence.vma");
    }

    pub fn map_region(&mut self, region: Box<dyn ASRegion>) {
        let dirs = region.map(self.root_pt, false);
        self.regions.insert(region.metadata().start, region);
        self.pt_dirs.extend(dirs);
    }

    pub fn unmap_region(&mut self, start: VirtPageNum) -> Option<Box<dyn ASRegion>> {
        self.regions
            .remove(&start)
            .inspect(|region| region.unmap(self.root_pt))
    }

    pub fn handle_page_fault(&mut self, addr: VirtAddr, perform: ASPerms) -> SyscallResult {
        let vpn = addr.floor();
        let region = self.regions
            .values_mut()
            .filter(|region| region.metadata().start <= vpn && region.metadata().end() > vpn)
            .next()
            .ok_or(Errno::EFAULT)?;

        let result = if region.metadata().perms.contains(perform) {
            region.fault_handler(self.root_pt, vpn)
        } else {
            info!("Page access violation: {:?} - {:?} / {:?}", addr, perform, region.metadata().perms);
            return Err(Errno::EACCES);
        };
        unsafe { self.activate(); }
        result
    }

    pub fn check_addr_valid(&self, start: VirtAddr, end: VirtAddr, perms: ASPerms) -> SyscallResult<()> {
        let vpn_start = start.floor();
        let vpn_end = end.ceil();
        let mut cur = vpn_start;
        for region in self.regions.values() {
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
                    return Err(Errno::EFAULT);
                }
            }
        }
        Err(Errno::EFAULT)
    }

    pub fn user_slice_r(&self, addr: VirtAddr, len: usize) -> SyscallResult<&'static [u8]> {
        if len == 0 {
            return Ok(&mut []);
        }
        self.check_addr_valid(addr, addr + len, ASPerms::R | ASPerms::U)?;
        let data = unsafe { core::slice::from_raw_parts(addr.as_ptr(), len) };
        Ok(data)
    }

    pub fn user_slice_w(&self, addr: VirtAddr, len: usize) -> SyscallResult<&'static mut [u8]> {
        if len == 0 {
            return Ok(&mut []);
        }
        self.check_addr_valid(addr, addr + len, ASPerms::W | ASPerms::U)?;
        let data = unsafe { core::slice::from_raw_parts_mut(addr.as_ptr(), len) };
        Ok(data)
    }

    pub fn user_slice_str(&self, addr: VirtAddr, max_len: usize) -> SyscallResult<&'static str> {
        let mut cur_len = min(max_len, PAGE_SIZE - addr.page_offset(2));
        while cur_len <= max_len {
            let data = self.user_slice_r(addr, cur_len)?;
            if let Ok(cstr) = CStr::from_bytes_until_nul(data) {
                return Ok(cstr.to_str().map_err(|_| Errno::EINVAL)?);
            }
            cur_len = min(cur_len + PAGE_SIZE, max_len);
        }
        Err(Errno::EINVAL)
    }

    pub fn set_brk(&mut self, addr: VirtAddr) -> SyscallResult<usize> {
        let heap_start = self.regions
            .values()
            .find(|region| region.metadata().name.as_deref() == Some("[heap]"))
            .map(|region| region.metadata().start)
            .unwrap();
        if addr.floor() < heap_start {
            return Ok(self.brk.0);
        }
        if let Some((upper_vpn, _)) = self.regions.range(heap_start..).skip(1).next() {
            if addr.floor() >= *upper_vpn {
                return Ok(self.brk.0);
            }
        }
        let mut brk = self.unmap_region(heap_start).unwrap();
        brk.resize((addr.ceil() - heap_start).0);
        self.map_region(brk);
        let prev = self.brk;
        self.brk = addr;
        Ok(prev.0)
    }

    pub fn mmap(
        &mut self,
        name: Option<String>,
        start: Option<VirtPageNum>,
        pages: usize,
        perms: ASPerms,
        inode: Option<Arc<dyn Inode>>,
        offset: usize,
        is_shared: bool,
    ) -> SyscallResult<usize> {
        if is_shared {
            warn!("Shared mapping is not supported yet");
        }
        let start = if let Some(start) = start {
            let end = start + pages;
            let is_overlap = self.regions
                .values()
                .any(|region| region.metadata().start < end && region.metadata().end() > start);
            if is_overlap {
                return Err(Errno::EINVAL);
            }
            start
        } else {
            let mut iter = self.regions
                .iter()
                .skip_while(|(_, region)| region.metadata().name.as_deref() != Some("[heap]"));
            let mut region_low = iter.next().unwrap().1;
            let mut region_high = iter.next().unwrap().1;
            while region_low.metadata().end() + pages > region_high.metadata().start {
                region_low = region_high;
                region_high = iter.next().unwrap().1;
            }
            region_low.metadata().end()
        };
        let metadata = ASRegionMeta { name, perms, start, pages };
        let region: Box<dyn ASRegion> = match inode {
            Some(inode) => FileRegion::new(metadata, Arc::downgrade(&inode), offset),
            None => LazyRegion::new_free(metadata),
        };
        self.map_region(region);
        Ok(VirtAddr::from(start).0)
    }

    pub fn munmap(&mut self, start: VirtPageNum, pages: usize) -> SyscallResult {
        let mut regions = vec![];
        for (vpn, region) in self.regions.range_mut(..start + pages) {
            if *vpn + pages <= start {
                continue;
            }
            if !region.metadata().perms.contains(ASPerms::U) {
                return Err(Errno::EPERM);
            }
            regions.push(*vpn);
        }
        for vpn in regions {
            self.unmap_region(vpn);
        }
        Ok(())
    }

    pub fn set_perms(&mut self, start: VirtPageNum, pages: usize, perms: ASPerms) -> SyscallResult {
        for (vpn, region) in self.regions.range_mut(..start + pages) {
            if *vpn + pages <= start {
                continue;
            }
            region.set_perms(perms);
            region.map(self.root_pt, true);
        }
        Ok(())
    }
}

impl AddressSpace {
    fn copy_global_mappings(&mut self) {
        for map in GLOBAL_MAPPINGS.iter() {
            debug!("Copy global mappings: {} from {:?} to {:?}", map.name, map.phys_start, map.phys_end());
            let ppn_start = PhysPageNum::from(map.phys_start);
            let vpn_start = VirtPageNum::from(map.virt_start);
            let vpn_end = VirtPageNum::from(map.virt_end());

            let metadata = ASRegionMeta {
                name: Some(map.name.to_string()),
                perms: map.perms,
                start: vpn_start,
                pages: (vpn_end - vpn_start).0,
            };
            let region = DirectRegion::new(metadata, ppn_start);
            self.map_region(region);
        }
    }

    fn map_trampoline(&mut self) -> SyscallResult {
        // li a7, 139; ecall
        let trampoline: [u8; 8] = bytemuck::cast([0x08b00893, 0x00000073]);
        let region = LazyRegion::new_framed(
            ASRegionMeta {
                name: Some("[trampoline]".to_string()),
                perms: ASPerms::R | ASPerms::X | ASPerms::U,
                start: TRAMPOLINE_BASE.into(),
                pages: 1,
            },
            &trampoline,
            0,
        )?;
        self.map_region(region);
        Ok(())
    }

    async fn load_linker(&mut self, mnt_ns: &MountNamespace, offset: usize) -> SyscallResult<usize> {
        let inode = mnt_ns.lookup_absolute("/libc.so").await?;
        let file = inode.open().unwrap();
        let elf_data = file.read_all().await.unwrap();
        let elf = ElfFile::new(&elf_data).map_err(|_| Errno::ENOEXEC)?;
        let ph_count = elf.header.pt2.ph_count();

        for i in 0..ph_count {
            let phdr = elf.program_header(i).map_err(|_| Errno::ENOEXEC)?;
            if phdr.get_type().map_err(|_| Errno::ENOEXEC)? == xmas_elf::program::Type::Load {
                let start_addr = VirtAddr(phdr.virtual_addr() as usize + offset);
                let end_addr = VirtAddr((phdr.virtual_addr() + phdr.mem_size()) as usize + offset);
                let start_vpn = start_addr.floor();
                let end_vpn = end_addr.ceil();

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
                    buf,
                    start_addr.page_offset(2),
                )?;
                self.map_region(region);
                debug!("Map linker section: {:?} - {:?}", start_vpn, end_vpn);
            }
        }
        Ok(elf.header.pt2.entry_point() as usize + offset)
    }
}
