use alloc::ffi::CString;
use alloc::string::ToString;
use alloc::vec;
use core::cmp::min;
use core::mem::size_of;
use log::{debug, warn};
use zerocopy::{AsBytes, FromBytes};
use crate::arch::{PAGE_SIZE, VirtAddr};
use crate::fs::fd::{FdNum, FileDescriptor};
use crate::fs::ffi::{AT_FDCWD, AT_REMOVEDIR, MAX_DIRENT_SIZE, DirentType, FcntlCmd, InodeMode, IoVec, KernelStat, LinuxDirent, MAX_NAME_LEN, OpenFlags, PATH_MAX};
use crate::fs::file::Seek;
use crate::fs::path::resolve_path;
use crate::fs::pipe::Pipe;
use crate::processor::current_process;
use crate::result::{Errno, SyscallResult};
use crate::sched::ffi::{TimeSpec, UTIME_NOW, UTIME_OMIT};
use crate::sched::time::current_time;

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
    proc_inner.fd_table.put(fd_impl, 0).map(|fd| fd as usize)
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

pub fn sys_fcntl(fd: FdNum, cmd: usize, arg2: usize) -> SyscallResult<usize> {
    let mut proc_inner = current_process().inner.lock();
    let mut fd_impl = proc_inner.fd_table.get(fd)?;
    let cmd = FcntlCmd::try_from(cmd).map_err(|_| Errno::EINVAL)?;
    match cmd {
        FcntlCmd::F_DUPFD => {
            return proc_inner.fd_table.put(fd_impl, arg2 as FdNum).map(|fd| fd as usize);
        }
        FcntlCmd::F_DUPFD_CLOEXEC => {
            let fd_impl = fd_impl.dup(true);
            return proc_inner.fd_table.put(fd_impl, arg2 as FdNum).map(|fd| fd as usize);
        }
        FcntlCmd::F_GETFD => {
            let flags = fd_impl.flags & OpenFlags::O_CLOEXEC;
            return Ok(flags.bits() as usize);
        }
        FcntlCmd::F_SETFD => {
            let flags = OpenFlags::from_bits(arg2 as u32).ok_or(Errno::EINVAL)?;
            let fd_impl = fd_impl.dup(flags.intersects(OpenFlags::O_CLOEXEC));
            proc_inner.fd_table.insert(fd, fd_impl)?;
        }
        FcntlCmd::F_GETFL => {
            let flags = fd_impl.flags & OpenFlags::O_STATUS;
            return Ok(flags.bits() as usize);
        }
        FcntlCmd::F_SETFL => {
            // TODO: Only change status flags
            warn!("F_SETFL");
            let flags = OpenFlags::from_bits(arg2 as u32).ok_or(Errno::EINVAL)?;
            fd_impl.flags = flags;
            proc_inner.fd_table.insert(fd, fd_impl)?;
        }
    }
    Ok(0)
}

pub async fn sys_ioctl(fd: FdNum, request: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> SyscallResult<usize> {
    let fd_impl = current_process().inner.lock().fd_table.get(fd)?;
    let ret = fd_impl.file.ioctl(request, arg2, arg3, arg4, arg5).await?;
    Ok(ret as usize)
}

pub async fn sys_mkdirat(dirfd: FdNum, path: usize, mode: u32) -> SyscallResult<usize> {
    let mut proc_inner = current_process().inner.lock();
    let path = proc_inner.addr_space.user_slice_str(VirtAddr(path), PATH_MAX)?;
    debug!("mkdirat: fd: {}, path: {:?}, mode: {:?}", dirfd, path, mode);
    let (parent, name) = path.rsplit_once('/').unwrap_or((".", path));
    let inode = resolve_path(&mut proc_inner, dirfd, parent).await?;
    if inode.metadata().mode != InodeMode::DIR {
        return Err(Errno::ENOTDIR);
    }
    inode.create(InodeMode::DIR, name).await?;
    Ok(0)
}

pub async fn sys_unlinkat(dirfd: FdNum, path: usize, flags: u32) -> SyscallResult<usize> {
    if flags & !AT_REMOVEDIR != 0 {
        return Err(Errno::EINVAL);
    }
    let proc_inner = current_process().inner.lock();
    let path = match path {
        0 => ".",
        _ => proc_inner.addr_space.user_slice_str(VirtAddr(path), PATH_MAX)?,
    };
    debug!("unlinkat: dirfd: {}, path: {:?}, flags: {:?}", dirfd, path, flags);
    let (parent, name) = path.rsplit_once('/').unwrap_or((".", path));
    let parent = resolve_path(&proc_inner, dirfd, parent).await?;
    let inode = parent.clone().lookup_name(name).await?;
    if inode.metadata().mode == InodeMode::DIR {
        if flags & AT_REMOVEDIR == 0 {
            return Err(Errno::EISDIR);
        }
        if inode.clone().lookup_idx(0).await.is_ok() {
            return Err(Errno::ENOTEMPTY);
        }
    } else {
        if flags & AT_REMOVEDIR != 0 {
            return Err(Errno::ENOTDIR);
        }
    }
    parent.unlink(name).await?;
    Ok(0)
}

pub async fn sys_umount2(target: usize, flags: u32) -> SyscallResult<usize> {
    warn!("umount2 is not implemented");
    Ok(0)
}

pub async fn sys_mount(source: usize, target: usize, fstype: usize, flags: u32, data: usize) -> SyscallResult<usize> {
    warn!("mount is not implemented");
    Ok(0)
}

pub fn sys_fstatfs(fd: FdNum, buf: usize) -> SyscallResult<usize> {
    let fd_impl = current_process().inner.lock().fd_table.get(fd)?;
    let inode = fd_impl.file.metadata().inode.clone().ok_or(Errno::ENOENT)?;
    if inode.metadata().mode != InodeMode::DIR {
        return Err(Errno::ENOTDIR);
    }
    // TODO: fstatfs
    Ok(0)
}

pub async fn sys_ftruncate(fd: FdNum, size: isize) -> SyscallResult<usize> {
    let fd_impl = current_process().inner.lock().fd_table.get(fd)?;
    if !fd_impl.flags.writable() {
        return Err(Errno::EBADF);
    }
    fd_impl.file.truncate(size).await?;
    Ok(0)
}

pub async fn sys_faccessat(fd: FdNum, path: usize, _mode: u32, _flags: u32) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let path = match path {
        0 => ".",
        _ => proc_inner.addr_space.user_slice_str(VirtAddr(path), PATH_MAX)?,
    };
    resolve_path(&proc_inner, fd, path).await?;
    Ok(0)
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
    debug!("openat: dirfd: {}, path: {:?}, flags: {:?}", dirfd, path, flags);
    let inode = match resolve_path(&mut proc_inner, dirfd, path).await {
        Ok(inode) => inode,
        Err(Errno::ENOENT) if flags.contains(OpenFlags::O_CREAT) => {
            let (parent, name) = path.rsplit_once('/').unwrap_or((".", path));
            let parent_inode = resolve_path(&mut proc_inner, dirfd, parent).await?;
            parent_inode.create(InodeMode::IFREG, name).await?
        }
        Err(e) => return Err(e),
    };
    let file = inode.open()?;
    let fd_impl = FileDescriptor::new(file, flags);
    let fd = proc_inner.fd_table.put(fd_impl, 0)?;
    Ok(fd as usize)
}

pub fn sys_close(fd: FdNum) -> SyscallResult<usize> {
    current_process().inner.lock().fd_table.remove(fd)?;
    Ok(0)
}

pub fn sys_pipe2(fds: usize, flags: u32) -> SyscallResult<usize> {
    let flags = OpenFlags::from_bits(flags).ok_or(Errno::EINVAL)?;
    let mut proc_inner = current_process().inner.lock();
    let user_fds = proc_inner.addr_space.user_slice_w(VirtAddr(fds), size_of::<[FdNum; 2]>())?;
    let (reader, writer) = Pipe::new();
    let reader_fd = proc_inner.fd_table.put(FileDescriptor::new(reader, OpenFlags::O_RDONLY | flags.intersection(OpenFlags::O_CLOEXEC)), 0)?;
    let writer_fd = proc_inner.fd_table.put(FileDescriptor::new(writer, OpenFlags::O_WRONLY | flags.intersection(OpenFlags::O_CLOEXEC)), 0)?;
    drop(proc_inner);
    user_fds.copy_from_slice(AsBytes::as_bytes(&[reader_fd, writer_fd]));
    Ok(0)
}

pub async fn sys_getdents(fd: FdNum, buf: usize, count: u32) -> SyscallResult<usize> {
    let fd_impl = current_process().inner.lock().fd_table.get(fd)?;
    let mut file_inner = fd_impl.file.metadata().inner.lock().await;
    let inode = fd_impl.file.metadata().inode.clone().ok_or(Errno::ENOENT)?;
    if inode.metadata().mode != InodeMode::DIR {
        return Err(Errno::ENOTDIR);
    }
    let mut cur = buf;
    for child in inode.list(file_inner.pos as usize).await? {
        let name = CString::new(child.metadata().name.as_str()).unwrap();
        let name_bytes = name.as_bytes_with_nul();
        let dirent_size = MAX_DIRENT_SIZE - (MAX_NAME_LEN - name_bytes.len());
        if cur + dirent_size > buf + count as usize {
            break;
        }
        let mut dirent = LinuxDirent {
            d_ino: child.metadata().ino as u64,
            d_off: 0,
            d_reclen: dirent_size as u16,
            d_type: DirentType::from(child.metadata().mode).bits(),
            d_name: [0; 256],
        };
        dirent.d_name[..name_bytes.len()].copy_from_slice(name_bytes);
        let user_buf = current_process().inner.lock().addr_space.user_slice_w(VirtAddr(cur), dirent_size)?;
        unsafe {
            user_buf.as_mut_ptr().cast::<LinuxDirent>().write(dirent);
        }
        file_inner.pos += 1;
        cur += dirent_size;
    }

    Ok(cur - buf)
}

pub async fn sys_lseek(fd: FdNum, offset: isize, whence: i32) -> SyscallResult<usize> {
    let fd_impl = current_process().inner.lock().fd_table.get(fd)?;
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
    drop(proc_inner);
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
    drop(proc_inner);
    let ret = fd_impl.file.write(user_buf).await?;
    Ok(ret as usize)
}

pub async fn sys_readv(fd: FdNum, iov: usize, iovcnt: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let fd_impl = proc_inner.fd_table.get(fd)?;
    if !fd_impl.flags.readable() {
        return Err(Errno::EBADF);
    }
    let user_buf = proc_inner.addr_space.user_slice_r(VirtAddr(iov), size_of::<IoVec>() * iovcnt)?;
    let iovs: &[IoVec] = unsafe { core::mem::transmute(user_buf) };
    drop(proc_inner);

    let mut ret = 0;
    for i in 0..iovcnt {
        let iov = &iovs[i];
        let user_buf = current_process().inner.lock().addr_space.user_slice_w(VirtAddr(iov.base), iov.len)?;
        ret += fd_impl.file.read(user_buf).await?;
    }
    Ok(ret as usize)
}

pub async fn sys_writev(fd: FdNum, iov: usize, iovcnt: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let fd_impl = proc_inner.fd_table.get(fd)?;
    if !fd_impl.flags.writable() {
        return Err(Errno::EBADF);
    }
    let user_buf = proc_inner.addr_space.user_slice_r(VirtAddr(iov), size_of::<IoVec>() * iovcnt)?;
    let iovs: &[IoVec] = unsafe { core::mem::transmute(user_buf) };
    drop(proc_inner);

    let mut ret = 0;
    for i in 0..iovcnt {
        let iov = &iovs[i];
        let user_buf = current_process().inner.lock().addr_space.user_slice_r(VirtAddr(iov.base), iov.len)?;
        ret += fd_impl.file.write(user_buf).await?;
    }

    Ok(ret as usize)
}

pub async fn sys_pread(fd: FdNum, buf: usize, len: usize, offset: isize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let fd_impl = proc_inner.fd_table.get(fd)?;
    if !fd_impl.flags.readable() {
        return Err(Errno::EBADF);
    }
    let user_buf = proc_inner.addr_space.user_slice_w(VirtAddr(buf), len)?;
    drop(proc_inner);
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
    drop(proc_inner);
    let ret = fd_impl.file.pwrite(user_buf, offset).await?;
    Ok(ret as usize)
}

pub async fn sys_sendfile(out_fd: FdNum, in_fd: FdNum, offset: usize, count: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let out_fd_impl = proc_inner.fd_table.get(out_fd)?;
    let in_fd_impl = proc_inner.fd_table.get(in_fd)?;
    if !out_fd_impl.flags.writable() || !in_fd_impl.flags.readable() {
        return Err(Errno::EBADF);
    }
    drop(proc_inner);
    let mut buf = vec![0; PAGE_SIZE];
    if offset == 0 {
        let mut sent = 0;
        while sent < count {
            let end = min(count - sent, buf.len());
            let read = in_fd_impl.file.read(&mut buf[..end]).await? as usize;
            if read == 0 {
                break;
            }
            out_fd_impl.file.write(&buf[..read]).await?;
            sent += read;
        }
        Ok(sent)
    } else {
        let user_buf = current_process().inner.lock().addr_space.user_slice_w(VirtAddr(offset), size_of::<usize>())?;
        let offset: usize = bytemuck::pod_read_unaligned(user_buf);
        let mut sent = 0;
        while sent < count {
            let end = min(count - sent, buf.len());
            let read = in_fd_impl.file.pread(&mut buf[..end], (offset + sent) as isize).await? as usize;
            if read == 0 {
                break;
            }
            out_fd_impl.file.write(&buf[..read]).await?;
            sent += read;
        }
        let write: [u8; size_of::<usize>()] = bytemuck::cast(offset + sent);
        user_buf.copy_from_slice(&write);
        Ok(sent)
    }
}

pub async fn sys_newfstatat(dirfd: FdNum, path: usize, buf: usize, _flags: u32) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let path = match path {
        0 => ".",
        _ => proc_inner.addr_space.user_slice_str(VirtAddr(path), PATH_MAX)?,
    };
    let inode = resolve_path(&proc_inner, dirfd, path).await?;
    let user_buf = proc_inner.addr_space.user_slice_w(VirtAddr(buf), size_of::<KernelStat>())?;
    drop(proc_inner);
    let mut stat = KernelStat::default();
    stat.st_dev = inode.metadata().dev as u64;
    stat.st_ino = inode.metadata().ino as u64;
    stat.st_mode = inode.metadata().mode as u32;
    let inner = inode.metadata().inner.lock();
    stat.st_nlink = inner.nlink as u32;
    stat.st_size = inner.size as u64;
    stat.st_atim = inner.atime;
    stat.st_mtim = inner.mtime;
    stat.st_ctim = inner.ctime;
    user_buf.copy_from_slice(stat.as_bytes());
    Ok(0)
}

pub fn sys_fstat(fd: FdNum, buf: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let fd_impl = proc_inner.fd_table.get(fd)?;
    let inode = fd_impl.file.metadata().inode.clone();
    let user_buf = proc_inner.addr_space.user_slice_w(VirtAddr(buf), size_of::<KernelStat>())?;
    drop(proc_inner);
    let mut stat = KernelStat::default();
    if let Some(inode) = inode {
        stat.st_dev = inode.metadata().dev as u64;
        stat.st_ino = inode.metadata().ino as u64;
        stat.st_mode = inode.metadata().mode as u32;
        let inner = inode.metadata().inner.lock();
        stat.st_nlink = inner.nlink as u32;
        stat.st_size = inner.size as u64;
        stat.st_atim = inner.atime;
        stat.st_mtim = inner.mtime;
        stat.st_ctim = inner.ctime;
    }
    user_buf.copy_from_slice(stat.as_bytes());
    Ok(0)
}

pub async fn sys_fsync(fd: FdNum) -> SyscallResult<usize> {
    let fd_impl = current_process().inner.lock().fd_table.get(fd)?;
    fd_impl.file.sync().await?;
    Ok(0)
}

pub async fn sys_utimensat(dirfd: FdNum, path: usize, times: usize, _flags: u32) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let path = match path {
        0 => ".",
        _ => proc_inner.addr_space.user_slice_str(VirtAddr(path), PATH_MAX)?,
    };
    let inode = resolve_path(&proc_inner, dirfd, path).await?;
    let now = TimeSpec::from(current_time());
    let (atime, mtime) = match times {
        0 => (Some(now), Some(now)),
        _ => {
            let times = proc_inner.addr_space.user_slice_r(VirtAddr(times), 2 * size_of::<TimeSpec>())?;
            let atime = TimeSpec::ref_from(&times[0..size_of::<TimeSpec>()]).unwrap();
            let mtime = TimeSpec::ref_from(&times[size_of::<TimeSpec>()..]).unwrap();
            let atime = match atime.nsec {
                UTIME_NOW => Some(now),
                UTIME_OMIT => None,
                _ => Some(*atime),
            };
            let mtime = match mtime.nsec {
                UTIME_NOW => Some(now),
                UTIME_OMIT => None,
                _ => Some(*mtime),
            };
            (atime, mtime)
        }
    };
    inode.metadata().inner.lock().apply_mut(|inner| {
        if let Some(atime) = atime {
            inner.atime = atime;
        }
        if let Some(mtime) = mtime {
            inner.mtime = mtime;
        }
        inner.ctime = now;
    });
    Ok(0)
}
