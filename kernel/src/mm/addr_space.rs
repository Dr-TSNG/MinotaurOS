use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::{format, vec};
use alloc::vec::Vec;
use core::cmp::{max, min};
use core::ffi::CStr;
use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicUsize, Ordering};
use bitflags::bitflags;
use lazy_static::lazy_static;
use log::{debug, info};
use lru::LruCache;
use xmas_elf::ElfFile;
use crate::arch::{PAGE_SIZE, PhysPageNum, VirtAddr, VirtPageNum};
use crate::config::{DYNAMIC_LINKER_BASE, TRAMPOLINE_BASE, USER_HEAP_SIZE, USER_STACK_SIZE, USER_STACK_TOP};
use crate::driver::GLOBAL_MAPPINGS;
use crate::fs::ffi::OpenFlags;
use crate::fs::file_system::MountNamespace;
use crate::fs::inode::Inode;
use crate::mm::allocator::{alloc_kernel_frames, HeapFrameTracker};
use crate::mm::page_table::PageTable;
use crate::mm::region::{ASRegion, ASRegionMeta};
use crate::mm::region::direct::DirectRegion;
use crate::mm::region::file::FileRegion;
use crate::mm::region::lazy::LazyRegion;
use crate::mm::region::shared::SharedRegion;
use crate::mm::sysv_shm::SysVShm;
use crate::process::aux::{self, Aux};
use crate::processor::hart::local_hart;
use crate::result::{Errno, SyscallResult};
use crate::sync::mutex::Mutex;

bitflags! {
    pub struct ASPerms: u8 {
        const R = 1 << 0;
        const W = 1 << 1;
        const X = 1 << 2;
        const U = 1 << 3;
    }
}

static TOKEN_COUNTER: AtomicUsize = AtomicUsize::new(0);

lazy_static! {
    static ref EXE_SNAPSHOTS: Mutex<LruCache<String, (AddressSpace, usize, Vec<Aux>)>> = {
        Mutex::new(LruCache::new(NonZeroUsize::new(4).unwrap()))
    };
}

pub struct AddressSpace {
    /// 地址空间标识
    pub token: usize,
    /// 根页表
    pub root_pt: PageTable,
    /// 地址空间中的区域
    regions: BTreeMap<VirtPageNum, Box<dyn ASRegion>>,
    /// 该地址空间关联的页表帧
    pt_dirs: Vec<HeapFrameTracker>,
    /// System V 共享内存 
    sysv_shm: Arc<Mutex<SysVShm>>,
    /// 当前 brk 指针
    brk: VirtAddr,
}

impl AddressSpace {
    pub fn new_bare() -> Self {
        let root_pt_page = alloc_kernel_frames(1);
        debug!("[addr_space] create root page table {:?}", root_pt_page.ppn);
        let mut addr_space = AddressSpace {
            token: TOKEN_COUNTER.fetch_add(1, Ordering::Relaxed),
            root_pt: PageTable::new(root_pt_page.ppn),
            regions: BTreeMap::new(),
            pt_dirs: vec![],
            sysv_shm: Default::default(),
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
            info!("[addr_space] {:?} {:x?} - {:x?}", region.metadata().name, start, end)
        }
        addr_space
    }

    pub async fn from_inode(
        mnt_ns: &MountNamespace,
        inode: Arc<dyn Inode>,
    ) -> SyscallResult<(Self, usize, Vec<Aux>)> {
        let exe = inode.mnt_ns_path(mnt_ns)?;
        let mut snapshots = EXE_SNAPSHOTS.lock();
        if let Some(cached) = snapshots.get_mut(&exe) {
            return Ok((cached.0.fork(), cached.1, cached.2.clone()));
        }
        drop(snapshots);

        let data = inode.open(OpenFlags::O_RDONLY)?.read_all().await?;
        let mut snapshot = Self::from_elf(mnt_ns, &data).await?;
        let this = (snapshot.0.fork(), snapshot.1, snapshot.2.clone());
        let mut snapshots = EXE_SNAPSHOTS.lock();
        snapshots.put(exe.to_string(), snapshot);

        Ok(this)
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
                            pages: end_vpn - start_vpn,
                        },
                        buf,
                        start_addr.page_offset(2),
                    )?;
                    max_end_vpn = region.metadata().end();
                    addr_space.map_region(region);
                    debug!("[addr_space] Map elf section: {:?} - {:?} for {:?}", start_vpn, end_vpn, perms);
                }
                xmas_elf::program::Type::Interp => {
                    linker_base = DYNAMIC_LINKER_BASE;
                    let linker = CStr::from_bytes_until_nul(&elf.input[phdr.offset() as usize..])
                        .unwrap().to_str().unwrap();
                    debug!("[addr_space] Load linker: {} at {:#x}", linker, linker_base);
                    entry = addr_space.load_linker(mnt_ns, linker, linker_base).await?;
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
            pages: ustack_top_vpn - ustack_bottom_vpn,
        });
        addr_space.map_region(region);
        debug!("[addr_space] Map user stack: {:?} - {:?}", ustack_bottom_vpn, ustack_top_vpn);

        // 映射用户堆
        let uheap_bottom_vpn = max_end_vpn;
        let uheap_top_vpn = uheap_bottom_vpn + USER_HEAP_SIZE / PAGE_SIZE;
        let region = LazyRegion::new_free(ASRegionMeta {
            name: Some("[heap]".to_string()),
            perms: ASPerms::U | ASPerms::R | ASPerms::W,
            start: uheap_bottom_vpn,
            pages: uheap_top_vpn - uheap_bottom_vpn,
        });
        addr_space.map_region(region);
        addr_space.brk = VirtAddr::from(uheap_top_vpn);
        debug!("[addr_space] Map user heap: {:?} - {:?}", uheap_bottom_vpn, uheap_top_vpn);

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
        let root_pt_page = alloc_kernel_frames(1);
        debug!("[addr_space] forked root page table {:?}", root_pt_page.ppn);
        let mut forked = AddressSpace {
            token: TOKEN_COUNTER.fetch_add(1, Ordering::Relaxed),
            root_pt: PageTable::new(root_pt_page.ppn),
            regions: BTreeMap::new(),
            pt_dirs: vec![],
            sysv_shm: self.sysv_shm.clone(),
            brk: self.brk,
        };
        forked.pt_dirs.push(root_pt_page);
        for region in self.regions.values_mut() {
            let forked_region = region.fork(self.root_pt);
            forked.map_region(forked_region);
        }
        forked
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
            info!("[addr_space] Page access violation: {:?} - {:?} / {:?}", addr, perform, region.metadata().perms);
            return Err(Errno::EACCES);
        };
        unsafe { local_hart().refresh_tlb(self.token); }
        result
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
                return Err(Errno::ENOMEM);
            }
        }
        let mut brk = self.unmap_region(heap_start).unwrap();
        let heap_end = brk.metadata().start + brk.metadata().pages;

        if addr.ceil() < heap_end {
            brk.split(0, heap_end - addr.ceil());
        } else if addr.ceil() > heap_end {
            brk.extend(addr.ceil() - heap_end);
        }
        self.brk = addr.ceil().into();
        self.map_region(brk);
        unsafe { local_hart().refresh_tlb(self.token); }
        Ok(self.brk.0)
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
        let start = if let Some(start) = start {
            self.munmap(start, pages)?;
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
            None if is_shared => SharedRegion::new_free(metadata),
            None => LazyRegion::new_free(metadata),
        };
        self.map_region(region);
        unsafe { local_hart().refresh_tlb(self.token); }
        Ok(VirtAddr::from(start).0)
    }

    pub fn munmap(&mut self, start: VirtPageNum, pages: usize) -> SyscallResult {
        let ret = self.modify_region(start, pages, |_| false);
        unsafe { local_hart().refresh_tlb(self.token); }
        ret
    }

    pub fn mprotect(&mut self, start: VirtPageNum, pages: usize, perms: ASPerms) -> SyscallResult {
        let ret = self.modify_region(start, pages, |region| {
            region.set_perms(perms);
            true
        });
        unsafe { local_hart().refresh_tlb(self.token); }
        ret
    }

    pub fn shmget(&self, pages: usize) -> SyscallResult<usize> {
        self.sysv_shm.lock().alloc(pages)
    }

    pub fn shmat(&mut self, id: usize, start: Option<VirtPageNum>) -> SyscallResult<usize> {
        let shm = self.sysv_shm.lock().get(id).ok_or(Errno::EINVAL)?;
        let start = if let Some(start) = start {
            self.munmap(start, shm.len())?;
            start
        } else {
            let mut iter = self.regions
                .iter()
                .skip_while(|(_, region)| region.metadata().name.as_deref() != Some("[heap]"));
            let mut region_low = iter.next().unwrap().1;
            let mut region_high = iter.next().unwrap().1;
            while region_low.metadata().end() + shm.len() > region_high.metadata().start {
                region_low = region_high;
                region_high = iter.next().unwrap().1;
            }
            region_low.metadata().end()
        };
        let metadata = ASRegionMeta {
            name: Some(format!("/dev/shm/{}", id)),
            perms: ASPerms::R | ASPerms::W | ASPerms::X | ASPerms::U,
            start,
            pages: shm.len(),
        };
        let region = SharedRegion::new_reffed(metadata, &shm);
        self.map_region(region);
        unsafe { local_hart().refresh_tlb(self.token); }
        Ok(VirtAddr::from(start).0)
    }
}

impl AddressSpace {
    fn modify_region(
        &mut self,
        start: VirtPageNum,
        pages: usize,
        f: impl Fn(&mut Box<dyn ASRegion>) -> bool,
    ) -> SyscallResult {
        let mut to_handle = vec![];
        for (vpn, region) in self.regions.range_mut(..start + pages) {
            if region.metadata().end() > start {
                if !region.metadata().perms.contains(ASPerms::U) {
                    return Err(Errno::EPERM);
                }
                to_handle.push(*vpn);
            }
        }
        let mut handled = vec![];
        for vpn in to_handle {
            let mut region = self.unmap_region(vpn).unwrap();
            let r_start = region.metadata().start;
            let r_end = region.metadata().end();
            let t_start = max(start, r_start);
            let t_end = min(start + pages, r_end);
            if r_start == t_start {
                if r_end == t_end {
                    if f(&mut region) {
                        handled.push(region);
                    }
                } else {
                    handled.extend(region.split(t_end - r_start, r_end - t_end));
                    if f(&mut region) {
                        handled.push(region);
                    }
                }
            } else {
                let mut split = region.split(0, t_start - r_start);
                let mut target = split.swap_remove(0);
                handled.push(region);
                handled.extend(split);
                if f(&mut target) {
                    handled.push(target);
                }
            }
        }
        for region in handled {
            self.map_region(region);
        }
        Ok(())
    }

    fn copy_global_mappings(&mut self) {
        for map in GLOBAL_MAPPINGS.iter() {
            debug!("[addr_space] Copy global mappings: {} from {:?} to {:?}", map.name, map.phys_start, map.phys_end());
            let ppn_start = PhysPageNum::from(map.phys_start);
            let vpn_start = VirtPageNum::from(map.virt_start);
            let vpn_end = VirtPageNum::from(map.virt_end());

            let metadata = ASRegionMeta {
                name: Some(map.name.to_string()),
                perms: map.perms,
                start: vpn_start,
                pages: vpn_end - vpn_start,
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

    async fn load_linker(
        &mut self,
        mnt_ns: &MountNamespace,
        linker: &str,
        offset: usize,
    ) -> SyscallResult<usize> {
        let inode = mnt_ns.lookup_absolute(linker, true).await?;
        let file = inode.open(OpenFlags::O_RDONLY).unwrap();
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
                        pages: end_vpn - start_vpn,
                    },
                    buf,
                    start_addr.page_offset(2),
                )?;
                self.map_region(region);
                debug!("[addr_space] Map linker section: {:?} - {:?}", start_vpn, end_vpn);
            }
        }
        Ok(elf.header.pt2.entry_point() as usize + offset)
    }
}
