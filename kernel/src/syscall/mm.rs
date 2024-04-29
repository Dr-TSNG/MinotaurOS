use crate::arch::{PAGE_SIZE, VirtAddr};
use crate::fs::fd::FdNum;
use crate::mm::ffi::{MapFlags, MapProt};
use crate::processor::current_process;
use crate::result::{Errno, SyscallResult};

pub fn sys_brk(addr: usize) -> SyscallResult<usize> {
    current_process().inner.lock().addr_space.set_brk(VirtAddr(addr))
}

pub fn sys_munmap(addr: usize, len: usize) -> SyscallResult<usize> {
    if addr % PAGE_SIZE != 0 {
        return Err(Errno::EINVAL);
    }
    current_process().inner.lock().addr_space.munmap(VirtAddr(addr).into(), len.div_ceil(PAGE_SIZE))?;
    Ok(0)
}

pub fn sys_mmap(addr: usize, len: usize, prot: u32, flags: u32, fd: FdNum, offset: usize) -> SyscallResult<usize> {
    if addr % PAGE_SIZE != 0 || offset % PAGE_SIZE != 0 {
        return Err(Errno::EINVAL);
    }
    let prot = MapProt::from_bits_truncate(prot);
    let flags = MapFlags::from_bits_truncate(flags);
    if flags.contains(MapFlags::MAP_PRIVATE) && flags.contains(MapFlags::MAP_SHARED) {
        return Err(Errno::EINVAL);
    }
    let start = match addr {
        0 => None,
        _ => flags.contains(MapFlags::MAP_FIXED).then_some(VirtAddr::from(addr).into()),
    };
    let is_shared = flags.contains(MapFlags::MAP_SHARED);
    let mut proc_inner = current_process().inner.lock();
    if !flags.contains(MapFlags::MAP_ANONYMOUS) && fd != -1 {
        let fd_impl = proc_inner.fd_table.get(fd)?;
        let inode = fd_impl.file.metadata().inode.clone().ok_or(Errno::ENODEV)?;
        inode.metadata().page_cache.as_ref().ok_or(Errno::ENODEV)?;
        let name = inode.metadata().path.clone();
        proc_inner.addr_space.mmap(Some(name), start, len.div_ceil(PAGE_SIZE), prot.into(), Some(inode), offset / PAGE_SIZE, is_shared)
    } else {
        proc_inner.addr_space.mmap(None, start, len.div_ceil(PAGE_SIZE), prot.into(), None, 0, is_shared)
    }
}
