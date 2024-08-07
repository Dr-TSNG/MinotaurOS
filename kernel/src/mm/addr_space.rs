use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::{format, vec};
use alloc::vec::Vec;
use core::cmp::{max, min};
use core::fmt::{Display, Formatter};
use core::num::NonZeroUsize;
use core::ops::Range;
use core::sync::atomic::{AtomicUsize, Ordering};
use bitflags::bitflags;
use goblin::elf::Elf;
use goblin::elf::header::ET_DYN;
use goblin::elf::program_header::PT_LOAD;
use lazy_static::lazy_static;
use log::{debug, info};
use lru::LruCache;
use crate::arch::{PAGE_SIZE, PhysPageNum, VirtAddr, VirtPageNum};
use crate::config::{DYNAMIC_LINKER_BASE, TRAMPOLINE_BASE, USER_HEAP_SIZE_MAX, USER_LOAD_BASE, USER_STACK_SIZE, USER_STACK_TOP};
use crate::driver::ffi::sep_dev;
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
use crate::process::token::AccessToken;
use crate::processor::hart::local_hart;
use crate::result::{Errno, SyscallResult};
use crate::sync::mutex::Mutex;

bitflags! {
    #[derive(Copy, Clone)]
    pub struct ASPerms: u8 {
        const R = 1 << 0;
        const W = 1 << 1;
        const X = 1 << 2;
        const U = 1 << 3;
        const S = 1 << 4;
        const RWX = Self::R.bits() | Self::W.bits() | Self::X.bits();
    }
}

impl Display for ASPerms {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let mut append = |flag: ASPerms, c: char| {
            if self.contains(flag) {
                write!(f, "{}", c)?;
            } else {
                write!(f, "-")?;
            }
            Ok(())
        };
        append(ASPerms::R, 'r')?;
        append(ASPerms::W, 'w')?;
        append(ASPerms::X, 'x')?;
        if self.contains(ASPerms::S) {
            append(ASPerms::U, 's')?;
        } else {
            append(ASPerms::U, 'p')?;
        }
        Ok(())
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
    /// 堆范围
    heap: Range<VirtPageNum>,
    /// 堆最大位置
    heap_max: VirtPageNum,
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
            heap: VirtPageNum(0)..VirtPageNum(0),
            heap_max: VirtPageNum(0),
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
        token: AccessToken,
    ) -> SyscallResult<(Self, usize, Vec<Aux>)> {
        let exe = inode.mnt_ns_path(mnt_ns)?;
        let mut snapshots = EXE_SNAPSHOTS.lock();
        if let Some(cached) = snapshots.get_mut(&exe) {
            return Ok((cached.0.fork(), cached.1, cached.2.clone()));
        }
        drop(snapshots);

        let dev = inode.metadata().dev;
        let ino = inode.metadata().ino;
        let data = inode.open(OpenFlags::O_RDONLY, token)?.read_all().await?;
        let mut snapshot = Self::from_elf(mnt_ns, &exe, dev, ino, &data, token).await?;
        let this = (snapshot.0.fork(), snapshot.1, snapshot.2.clone());
        let mut snapshots = EXE_SNAPSHOTS.lock();
        snapshots.put(exe.to_string(), snapshot);

        Ok(this)
    }

    pub async fn from_elf(
        mnt_ns: &MountNamespace,
        name: &str,
        dev: u64,
        ino: usize,
        data: &[u8],
        token: AccessToken,
    ) -> SyscallResult<(Self, usize, Vec<Aux>)> {
        let mut addr_space = Self::new_bare();
        addr_space.copy_global_mappings();
        addr_space.map_trampoline()?;
        let elf = Elf::parse(data).map_err(|_| Errno::ENOEXEC)?;
        let offset = match elf.header.e_type {
            ET_DYN => USER_LOAD_BASE,
            _ => VirtAddr(0),
        };

        let mut entry = offset + elf.entry as usize;
        if let Some(linker) = elf.interpreter {
            debug!("[addr_space] Load linker: {} at {:?}", linker, DYNAMIC_LINKER_BASE);
            entry = addr_space.load_linker(mnt_ns, linker, token).await?;
        }

        let mut load_base = None;
        let mut max_end_vpn = VirtPageNum(0);
        for phdr in elf.program_headers {
            if phdr.p_type == PT_LOAD {
                let start_addr = offset + phdr.p_vaddr as usize;
                let end_addr = start_addr + phdr.p_memsz as usize;
                let start_vpn = start_addr.floor();
                let end_vpn = end_addr.ceil();
                if load_base.is_none() {
                    load_base = Some(start_addr);
                }

                let mut perms = ASPerms::U;
                if phdr.is_read() {
                    perms |= ASPerms::R;
                }
                if phdr.is_write() {
                    perms |= ASPerms::W;
                }
                if phdr.is_executable() {
                    perms |= ASPerms::X;
                }
                let region = LazyRegion::new_framed(
                    ASRegionMeta {
                        name: Some(name.to_string()),
                        perms,
                        start: start_vpn,
                        pages: end_vpn - start_vpn,
                        offset: phdr.p_offset as usize,
                        dev,
                        ino,
                    },
                    &data[phdr.file_range()],
                    start_addr.page_offset(2),
                )?;
                max_end_vpn = region.metadata().end();
                addr_space.map_region(region);
                debug!("[addr_space] Map elf section: {:?} - {:?} for {}", start_vpn, end_vpn, perms);
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
            offset: 0,
            dev: 0,
            ino: 0,
        });
        addr_space.map_region(region);
        debug!("[addr_space] Map user stack: {:?} - {:?}", ustack_bottom_vpn, ustack_top_vpn);

        // 映射用户堆（只映射一个空闲区域）
        let region = LazyRegion::new_free(ASRegionMeta {
            name: Some("[heap]".to_string()),
            perms: ASPerms::U | ASPerms::R | ASPerms::W,
            start: max_end_vpn,
            pages: max_end_vpn - max_end_vpn,
            offset: 0,
            dev: 0,
            ino: 0,
        });
        addr_space.map_region(region);
        addr_space.heap = max_end_vpn..max_end_vpn;
        addr_space.heap_max = max_end_vpn + USER_HEAP_SIZE_MAX / PAGE_SIZE;
        debug!("[addr_space] Map user heap: {:?} - {:?}", max_end_vpn, max_end_vpn);

        let mut auxv: Vec<Aux> = Vec::with_capacity(64);
        auxv.push(Aux::new(aux::AT_PHDR, load_base.unwrap().0 + elf.header.e_phoff as usize));
        auxv.push(Aux::new(aux::AT_PHENT, elf.header.e_phentsize as usize));
        auxv.push(Aux::new(aux::AT_PHNUM, elf.header.e_phnum as usize));
        auxv.push(Aux::new(aux::AT_PAGESZ, PAGE_SIZE));
        auxv.push(Aux::new(aux::AT_BASE, DYNAMIC_LINKER_BASE.0));
        auxv.push(Aux::new(aux::AT_FLAGS, 0));
        auxv.push(Aux::new(aux::AT_ENTRY, offset.0 + elf.header.e_entry as usize));
        auxv.push(Aux::new(aux::AT_UID, 0));
        auxv.push(Aux::new(aux::AT_EUID, 0));
        auxv.push(Aux::new(aux::AT_GID, 0));
        auxv.push(Aux::new(aux::AT_EGID, 0));

        Ok((addr_space, entry.0, auxv))
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
            heap: self.heap.clone(),
            heap_max: self.heap_max,
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

        if region.metadata().perms.contains(perform) {
            self.pt_dirs.extend(region.fault_handler(self.root_pt, vpn)?);
            unsafe { local_hart().refresh_tlb(self.token); }
            Ok(())
        } else {
            info!("[addr_space] Page access violation: {:?} - {} / {}", addr, perform, region.metadata().perms);
            Err(Errno::EFAULT)
        }
    }

    pub fn set_brk(&mut self, addr: VirtAddr) -> SyscallResult<VirtPageNum> {
        let heap_end = self.heap.end;
        if addr.floor() < self.heap.start {
            return Ok(heap_end);
        }
        if addr.floor() >= self.heap_max {
            return Err(Errno::ENOMEM);
        }
        let brk = self.regions.get_mut(&self.heap.start).unwrap();
        if addr.ceil() < heap_end {
            brk.split(0, heap_end - addr.ceil());
            // 只有减少堆大小时才需要即时更新页表，增加堆大小时会在下次访问时更新
            self.pt_dirs.extend(brk.map(self.root_pt, true));
            unsafe { local_hart().refresh_tlb(self.token); }
        } else if addr.ceil() > heap_end {
            brk.extend(addr.ceil() - heap_end);
        }
        self.heap.end = addr.ceil();
        Ok(self.heap.end)
    }

    pub fn mmap(
        &mut self,
        name: Option<String>,
        start: Option<VirtPageNum>,
        pages: usize,
        perms: ASPerms,
        inode: Option<Arc<dyn Inode>>,
        offset: usize,
    ) -> SyscallResult<usize> {
        let start = if let Some(start) = start {
            self.munmap(start, pages)?;
            start
        } else {
            let mut iter = self.regions.range(self.heap_max..);
            let mut left = self.heap_max;
            let (mut right, mut region) = iter.next().unwrap();
            while left + pages > *right {
                left = region.metadata().end();
                (right, region) = iter.next().unwrap();
            }
            left
        };
        let mut metadata = ASRegionMeta { name, perms, start, pages, offset, dev: 0, ino: 0 };
        let region: Box<dyn ASRegion> = match inode {
            Some(inode) => {
                metadata.dev = inode.metadata().dev;
                metadata.ino = inode.metadata().ino;
                FileRegion::new(metadata, inode.page_cache().unwrap())
            }
            None if perms.contains(ASPerms::S) => SharedRegion::new_free(metadata),
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
            let mut iter = self.regions.range(self.heap_max..);
            let mut left = self.heap_max;
            let (mut right, mut region) = iter.next().unwrap();
            while left + shm.len() > *right {
                left = region.metadata().end();
                (right, region) = iter.next().unwrap();
            }
            left
        };
        let metadata = ASRegionMeta {
            name: Some(format!("/dev/shm/{}", id)),
            perms: ASPerms::U | ASPerms::S | ASPerms::R | ASPerms::W | ASPerms::X,
            start,
            pages: shm.len(),
            offset: 0,
            dev: 0,
            ino: 0,
        };
        let region = SharedRegion::new_reffed(metadata, &shm);
        self.map_region(region);
        unsafe { local_hart().refresh_tlb(self.token); }
        Ok(VirtAddr::from(start).0)
    }

    pub fn display_maps(&self) -> Vec<String> {
        let mut maps = vec![];
        for region in self.regions.values() {
            if !region.metadata().perms.contains(ASPerms::U) {
                continue;
            }
            let start: VirtAddr = region.metadata().start.into();
            let end: VirtAddr = region.metadata().end().into();
            let perms = region.metadata().perms;
            let off = region.metadata().offset;
            let dev = region.metadata().dev;
            let ino = region.metadata().ino;
            let (major, minor) = sep_dev(dev);
            let name = region.metadata().name.as_deref().unwrap_or("");
            let mut entry = format!(
                "{:x}-{:x} {} {:08} {:02x}:{:02x} {}",
                start.0, end.0, perms, off, major, minor, ino,
            );
            let padding = 72usize.checked_sub(entry.len()).unwrap_or(0) + 1;
            entry.push_str(&" ".repeat(padding));
            entry.push_str(name);
            entry.push('\n');
            maps.push(entry);
        }
        maps
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
                offset: 0,
                dev: 0,
                ino: 0,
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
                perms: ASPerms::U | ASPerms::R | ASPerms::X,
                start: TRAMPOLINE_BASE.into(),
                pages: 1,
                offset: 0,
                dev: 0,
                ino: 0,
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
        token: AccessToken,
    ) -> SyscallResult<VirtAddr> {
        let inode = mnt_ns.lookup_absolute(linker, true, token).await?;
        let file = inode.clone().open(OpenFlags::O_RDONLY, AccessToken::root()).unwrap();
        let data = file.read_all().await.unwrap();
        let elf = Elf::parse(&data).map_err(|_| Errno::ENOEXEC)?;

        for phdr in elf.program_headers {
            if phdr.p_type == PT_LOAD {
                let start_addr = DYNAMIC_LINKER_BASE + phdr.p_vaddr as usize;
                let end_addr = start_addr + phdr.p_memsz as usize;
                let start_vpn = start_addr.floor();
                let end_vpn = end_addr.ceil();

                let mut perms = ASPerms::U;
                if phdr.is_read() {
                    perms |= ASPerms::R;
                }
                if phdr.is_write() {
                    perms |= ASPerms::W;
                }
                if phdr.is_executable() {
                    perms |= ASPerms::X;
                }
                let region = LazyRegion::new_framed(
                    ASRegionMeta {
                        name: Some(linker.to_string()),
                        perms,
                        start: start_vpn,
                        pages: end_vpn - start_vpn,
                        offset: phdr.p_offset as usize,
                        dev: inode.metadata().dev,
                        ino: inode.metadata().ino,
                    },
                    &data[phdr.file_range()],
                    start_addr.page_offset(2),
                )?;
                self.map_region(region);
                debug!("[addr_space] Map linker section: {:?} - {:?}", start_vpn, end_vpn);
            }
        }
        Ok(DYNAMIC_LINKER_BASE + elf.header.e_entry as usize)
    }
}
