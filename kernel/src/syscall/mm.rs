use crate::arch::{PAGE_SIZE, VirtAddr, VirtPageNum};
use crate::fs::fd::FdNum;
use crate::mm::ffi::{MapFlags, MapProt};
use crate::processor::current_process;
use crate::result::{Errno, SyscallResult};

pub fn sys_brk(addr: usize) -> SyscallResult<usize> {
    let mut proc_inner = current_process().inner.lock();
    proc_inner.addr_space.set_brk(VirtAddr::from(addr))?;
    Ok(0)
}

pub fn sys_mmap(addr: usize, len: usize, prot: u32, flags: u32, fd: FdNum, offset: usize) -> SyscallResult<usize> {
    if addr % PAGE_SIZE != 0 || len % PAGE_SIZE != 0 {
        return Err(Errno::EINVAL);
    }
    let start = match addr {
        0 => None,
        _ => Some(VirtAddr::from(addr).into()),
    };
    let prot = MapProt::from_bits_truncate(prot);
    let flags = MapFlags::from_bits_truncate(flags);
    let mut proc_inner = current_process().inner.lock();
    if fd != -1 {
        todo!("mmap with file");
    } else {
        proc_inner.addr_space.create_region(start, len / PAGE_SIZE, prot.into())
    }
}
