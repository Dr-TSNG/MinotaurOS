use alloc::ffi::CString;
use alloc::string::ToString;
use core::ptr::copy_nonoverlapping;
use log::trace;
use crate::arch::VirtAddr;
use crate::fs::fd::{FdNum, FileDescriptor};
use crate::fs::ffi::{AT_FDCWD, DIRENT_SIZE, DirentType, InodeMode, LinuxDirent, MAX_NAME_LEN, OpenFlags, PATH_MAX};
use crate::fs::file::Seek;
use crate::fs::path::resolve_path;
use crate::processor::current_process;
use crate::result::{Errno, SyscallResult};

pub fn sys_getcwd(buf: usize, size: usize) -> SyscallResult<usize> {
    if buf == 0 || size == 0 {
        return Err(Errno::EINVAL);
    }
    let proc_inner = current_process().inner.lock();
    let cwd = proc_inner.cwd.clone();
    if cwd.len() + 1 > size {
        return Err(Errno::ERANGE);
    }
    let user_buf = proc_inner.addr_space.user_slice_w(VirtAddr(buf), size)?;
    drop(proc_inner);

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

pub async fn sys_chdir(path: usize) -> SyscallResult<usize> {
    let mut proc_inner = current_process().inner.lock();
    let path = proc_inner.addr_space.user_slice_str(VirtAddr(path), PATH_MAX)?;
    resolve_path(&mut proc_inner, AT_FDCWD, path).await?;
    proc_inner.cwd = path.to_string();
    Ok(0)
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

pub fn sys_close(fd: FdNum) -> SyscallResult<usize> {
    let mut proc_inner = current_process().inner.lock();
    proc_inner.fd_table.remove(fd)?;
    Ok(0)
}

pub async fn sys_getdents(fd: FdNum, buf: usize, count: u32) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let fd_impl = proc_inner.fd_table.get(fd)?;
    if !fd_impl.flags.contains(OpenFlags::O_DIRECTORY) {
        return Err(Errno::ENOTDIR);
    }

    let file_inner = fd_impl.file.metadata().inner.lock().await;
    let inode = fd_impl.file.metadata().inode.clone();
    let mut cur = buf;
    for child in inode.list(file_inner.pos as usize).await? {
        if cur + DIRENT_SIZE > buf + count as usize {
            break;
        }
        let name = CString::new(child.metadata().name.as_str()).unwrap();
        let name_bytes = name.as_bytes_with_nul();
        let mut dirent = LinuxDirent {
            d_ino: child.metadata().ino as u64,
            d_off: 0,
            d_reclen: DIRENT_SIZE as u16 - (MAX_NAME_LEN - name_bytes.len()) as u16,
            d_type: DirentType::from(child.metadata().mode).bits(),
            d_name: [0; 256],
        };
        dirent.d_name[..name_bytes.len()].copy_from_slice(name_bytes);
        let user_buf = proc_inner.addr_space.user_slice_w(VirtAddr(cur), DIRENT_SIZE)?;
        unsafe {
            copy_nonoverlapping(&dirent, user_buf.as_mut_ptr() as *mut LinuxDirent, 1);
        }
        cur += DIRENT_SIZE;
    }

    Ok(cur - buf)
}

pub async fn sys_lseek(fd: FdNum, offset: isize, whence: i32) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let fd_impl = proc_inner.fd_table.get(fd)?;
    let seek = Seek::try_from((whence, offset))?;
    let ret = fd_impl.file.seek(seek).await?;
    Ok(ret as usize)
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

pub async fn sys_pread(fd: FdNum, buf: usize, len: usize, offset: isize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let fd_impl = proc_inner.fd_table.get(fd)?;
    if !fd_impl.flags.readable() {
        return Err(Errno::EBADF);
    }
    let user_buf = proc_inner.addr_space.user_slice_w(VirtAddr(buf), len)?;
    let ret = fd_impl.file.pread(user_buf, offset).await?;
    Ok(ret as usize)
}

pub async fn sys_pwrite(fd: FdNum, buf: usize, len: usize, offset: isize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let fd_impl = proc_inner.fd_table.get(fd)?;
    if !fd_impl.flags.writable() {
        return Err(Errno::EBADF);
    }
    let user_buf = proc_inner.addr_space.user_slice_r(VirtAddr(buf), len)?;
    let ret = fd_impl.file.pwrite(user_buf, offset).await?;
    Ok(ret as usize)
}
