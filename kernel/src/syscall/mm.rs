use log::{debug, warn};
use crate::arch::{PAGE_SIZE, VirtAddr};
use crate::fs::fd::FdNum;
use crate::mm::addr_space::ASPerms;
use crate::mm::ffi::{IPC_PRIVATE, MapFlags, MapProt};
use crate::processor::current_process;
use crate::result::{Errno, SyscallResult};

pub fn sys_shmget(key: usize, len: usize, _flags: u32) -> SyscallResult<usize> {
    if len % PAGE_SIZE != 0 {
        return Err(Errno::EINVAL);
    }
    if key != IPC_PRIVATE {
        // TODO: Non-IPC_PRIVATE shmget
        warn!("[shmget] Non-IPC_PRIVATE is not supported");
        return Err(Errno::ENOSYS);
    }
    debug!("[shmget] key: {}, len: {}", key, len);
    current_process().inner.lock().addr_space.lock().shmget(len / PAGE_SIZE)
}

pub fn sys_shmctl(_shmid: i32, _op: i32, _buf: usize) -> SyscallResult<usize> {
    warn!("sys_shmctl: unimplemented");
    Ok(0)
}

pub fn sys_shmat(shmid: i32, addr: usize, _flags: u32) -> SyscallResult<usize> {
    if addr % PAGE_SIZE != 0 {
        return Err(Errno::EINVAL);
    }
    let start = match addr {
        0 => None,
        _ => Some(VirtAddr(addr).into()),
    };
    debug!("[shmat] shmid: {}, addr: {:?}", shmid, VirtAddr(addr));
    current_process().inner.lock().addr_space.lock().shmat(shmid as usize, start)
}

pub fn sys_brk(addr: usize) -> SyscallResult<usize> {
    let va = current_process().inner.lock().addr_space.lock().set_brk(VirtAddr(addr))?;
    debug!("[brk] {:#x} -> {:#x}", addr, va);
    Ok(va)
}

pub fn sys_munmap(addr: usize, len: usize) -> SyscallResult<usize> {
    if addr % PAGE_SIZE != 0 {
        return Err(Errno::EINVAL);
    }
    current_process().inner.lock().addr_space.lock()
        .munmap(VirtAddr(addr).into(), len.div_ceil(PAGE_SIZE))?;
    Ok(0)
}

pub fn sys_mmap(addr: usize, len: usize, prot: u32, flags: u32, fd: FdNum, offset: usize) -> SyscallResult<usize> {
    if addr % PAGE_SIZE != 0 || offset % PAGE_SIZE != 0 {
        return Err(Errno::EINVAL);
    }
    let prot = MapProt::from_bits_truncate(prot);
    let flags = MapFlags::from_bits_truncate(flags);
    let start = match addr {
        0 => None,
        _ => flags.contains(MapFlags::MAP_FIXED).then_some(VirtAddr(addr).into()),
    };
    debug!(
        "[mmap] start: {:?}, len: {:#x}, prot: {:?}, flags: {:?}, fd: {:?}, offset: {}",
        start, len, prot, flags, fd, offset,
    );
    let mut perms = ASPerms::from(prot);
    if flags.contains(MapFlags::MAP_SHARED) {
        perms |= ASPerms::S;
    } else if !flags.contains(MapFlags::MAP_PRIVATE) {
        return Err(Errno::EINVAL);
    }
    let proc_inner = current_process().inner.lock();
    if !flags.contains(MapFlags::MAP_ANONYMOUS) && fd != -1 {
        let fd_impl = proc_inner.fd_table.get(fd)?;
        let inode = fd_impl.file.metadata().inode.clone().ok_or(Errno::ENODEV)?;
        inode.metadata().page_cache.as_ref().ok_or(Errno::ENODEV)?;
        let name = inode.mnt_ns_path(&proc_inner.mnt_ns)?;
        proc_inner.addr_space.lock()
            .mmap(Some(name), start, len.div_ceil(PAGE_SIZE), perms, Some(inode), offset)
    } else {
        proc_inner.addr_space.lock()
            .mmap(None, start, len.div_ceil(PAGE_SIZE), perms, None, 0)
    }
}

pub fn sys_mprotect(addr: usize, len: usize, prot: u32) -> SyscallResult<usize> {
    if addr % PAGE_SIZE != 0 {
        return Err(Errno::EINVAL);
    }
    let prot = MapProt::from_bits_truncate(prot);
    debug!("[mprotect] addr: {:?}, len: {}, prot: {:?}",VirtAddr(addr), len, prot);
    current_process().inner.lock().addr_space.lock()
        .mprotect(VirtAddr(addr).into(), len.div_ceil(PAGE_SIZE), prot.into())?;
    Ok(0)
}
