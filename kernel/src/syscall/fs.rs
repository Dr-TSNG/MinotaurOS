use log::trace;
use crate::arch::VirtAddr;
use crate::fs::fd::{FdNum, FileDescriptor};
use crate::fs::ffi::{InodeMode, OpenFlags, PATH_MAX};
use crate::fs::path::resolve_path;
use crate::processor::current_process;
use crate::result::{Errno, SyscallResult};

pub fn sys_getcwd(buf: usize, size: usize) -> SyscallResult<usize> {
    if buf == 0 || size == 0 {
        return Err(Errno::EINVAL);
    }
    if size > PATH_MAX {
        return Err(Errno::ENAMETOOLONG);
    }
    let proc_inner = current_process().inner.lock();
    let cwd = proc_inner.cwd.as_str();
    if cwd.len() + 1 > size {
        return Err(Errno::ERANGE);
    }
    let user_buf = proc_inner.addr_space.user_slice_w(VirtAddr(buf), size)?;
    user_buf[..cwd.len()].copy_from_slice(cwd.as_bytes());
    user_buf[cwd.len()] = b'\0';
    Ok(buf)
}

pub fn sys_dup(fd: FdNum) -> SyscallResult<usize> {
    let mut proc_inner = current_process().inner.lock();
    let fd_impl = proc_inner.fd_table.get(fd)?.dup(false);
    proc_inner.fd_table.put(fd_impl).map(|fd| fd as usize)
}

pub fn sys_dup3(old_fd: FdNum, new_fd: FdNum, flags: u32) -> SyscallResult<usize> {
    if old_fd == new_fd {
        return Err(Errno::EINVAL);
    }
    let cloexec = OpenFlags::from_bits(flags).and_then(|flags| {
        const EMPTY: OpenFlags = OpenFlags::empty();
        match flags {
            EMPTY => Some(false),
            OpenFlags::O_CLOEXEC => Some(true),
            _ => None,
        }
    }).ok_or(Errno::EINVAL)?;
    let mut proc_inner = current_process().inner.lock();
    let fd_impl = proc_inner.fd_table.get(old_fd)?.dup(cloexec);
    proc_inner.fd_table.insert(new_fd, fd_impl)?;
    Ok(new_fd as usize)
}

pub async fn sys_openat(dirfd: FdNum, path: usize, flags: u32, _mode: u32) -> SyscallResult<usize> {
    let flags = OpenFlags::from_bits(flags).ok_or(Errno::EINVAL)?;
    let mut proc_inner = current_process().inner.lock();
    let path = match path {
        0 => ".",
        _ => proc_inner.addr_space.user_slice_str(VirtAddr(path), PATH_MAX)?,
    };
    trace!("openat: dirfd: {}, path: {:?}, flags: {:?}", dirfd, path, flags);
    let inode = resolve_path(&mut proc_inner, dirfd, path).await?;
    if flags.contains(OpenFlags::O_DIRECTORY) {
        if inode.metadata().mode != InodeMode::DIR {
            return Err(Errno::ENOTDIR);
        }
    } else {
        if inode.metadata().mode == InodeMode::DIR {
            return Err(Errno::EISDIR);
        }
    }
    let file = inode.open()?;
    let fd_impl = FileDescriptor::new(file, flags);
    let fd = proc_inner.fd_table.put(fd_impl)?;
    Ok(fd as usize)
}

pub async fn sys_read(fd: FdNum, buf: usize, len: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let fd_impl = proc_inner.fd_table.get(fd)?;
    if !fd_impl.flags.readable() {
        return Err(Errno::EBADF);
    }
    let user_buf = proc_inner.addr_space.user_slice_w(VirtAddr(buf), len)?;
    let ret = fd_impl.file.read(user_buf).await?;
    Ok(ret as usize)
}

pub async fn sys_write(fd: FdNum, buf: usize, len: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let fd_impl = proc_inner.fd_table.get(fd)?;
    if !fd_impl.flags.writable() {
        return Err(Errno::EBADF);
    }
    let user_buf = proc_inner.addr_space.user_slice_r(VirtAddr(buf), len)?;
    let ret = fd_impl.file.write(user_buf).await?;
    Ok(ret as usize)
}
