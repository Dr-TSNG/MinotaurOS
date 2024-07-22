use alloc::ffi::CString;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;
use core::ffi::CStr;
use core::mem::size_of;
use core::time::Duration;
use log::{debug, info, warn};
use tap::Tap;
use zerocopy::{AsBytes, FromBytes, FromZeroes};
use macros::suspend;
use crate::arch::{PAGE_SIZE, VirtAddr};
use crate::fs::devfs::DevFileSystem;
use crate::fs::fd::{FdNum, FileDescriptor};
use crate::fs::ffi::{AT_FDCWD, AT_REMOVEDIR, MAX_DIRENT_SIZE, DirentType, FcntlCmd, InodeMode, IoVec, KernelStat, LinuxDirent, MAX_NAME_LEN, OpenFlags, PATH_MAX, RenameFlags, PollFd, VfsFlags, FdSet, FD_SET_LEN, PollEvents, KernelStatfs, AT_SYMLINK_NOFOLLOW};
use crate::fs::file::Seek;
use crate::fs::path::{resolve_path, split_last_path};
use crate::fs::pipe::Pipe;
use crate::fs::procfs::ProcFileSystem;
use crate::fs::tmpfs::TmpFileSystem;
use crate::process::thread::event_bus::Event;
use crate::processor::{current_process, current_thread};
use crate::result::{Errno, SyscallResult};
use crate::sched::ffi::{TimeSpec, TimeVal, UTIME_NOW, UTIME_OMIT};
use crate::sched::iomultiplex::{FdSetRWE, IOFormat, IOMultiplexFuture};
use crate::sched::suspend_now;
use crate::sched::time::real_time;
use crate::signal::ffi::SigSet;

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
    let fd_impl = proc_inner.fd_table.get(fd)?;
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
    let fd_impl = proc_inner.fd_table.get(old_fd)?.tap_mut(|it| it.cloexec = cloexec);
    proc_inner.fd_table.insert(new_fd, fd_impl)?;
    Ok(new_fd as usize)
}

pub fn sys_fcntl(fd: FdNum, cmd: usize, arg2: usize) -> SyscallResult<usize> {
    let cmd = FcntlCmd::try_from(cmd).map_err(|_| Errno::EINVAL)?;
    debug!("[fcntl] fd: {}, cmd: {:?}, arg2: {}", fd, cmd, arg2);
    let proc_inner = &mut *current_process().inner.lock();
    let fd_impl = proc_inner.fd_table.get_mut(fd)?;
    match cmd {
        FcntlCmd::F_DUPFD => {
            let new_fd_impl = fd_impl.clone();
            proc_inner.fd_table.put(new_fd_impl, arg2 as FdNum).map(|fd| fd as usize)
        }
        FcntlCmd::F_DUPFD_CLOEXEC => {
            let new_fd_impl = fd_impl.clone().tap_mut(|it| it.cloexec = true);
            proc_inner.fd_table.put(new_fd_impl, arg2 as FdNum).map(|fd| fd as usize)
        }
        FcntlCmd::F_GETFD => {
            Ok(fd_impl.cloexec as usize)
        }
        FcntlCmd::F_SETFD => {
            let flags = OpenFlags::from_bits(arg2 as u32).ok_or(Errno::EINVAL)?;
            fd_impl.cloexec = flags.contains(OpenFlags::O_CLOEXEC);
            Ok(0)
        }
        FcntlCmd::F_GETFL => {
            let flags = fd_impl.file.metadata().flags.lock();
            Ok(flags.bits() as usize)
        }
        FcntlCmd::F_SETFL => {
            let new_flags = OpenFlags::from_bits(arg2 as u32).ok_or(Errno::EINVAL)?;
            let mut old_flags = fd_impl.file.metadata().flags.lock();
            *old_flags = (*old_flags - OpenFlags::O_STATUS) | (new_flags & OpenFlags::O_STATUS);
            Ok(0)
        }
    }
}

pub async fn sys_ioctl(fd: FdNum, request: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> SyscallResult<usize> {
    let fd_impl = current_process().inner.lock().fd_table.get(fd)?;
    let ret = fd_impl.file.ioctl(request, arg2, arg3, arg4, arg5).await?;
    Ok(ret as usize)
}

pub async fn sys_mkdirat(dirfd: FdNum, path: usize, mode: u32) -> SyscallResult<usize> {
    let path = current_process().inner.lock()
        .addr_space.transmute_str(path, PATH_MAX)?.ok_or(Errno::EINVAL)?;
    debug!("[mkdirat] fd: {}, path: {:?}, mode: {:?}", dirfd, path, mode);
    let (parent, name) = split_last_path(path).ok_or(Errno::EEXIST)?;
    let inode = resolve_path(dirfd, &parent, true).await?;
    if inode.metadata().mode != InodeMode::IFDIR {
        return Err(Errno::ENOTDIR);
    }
    inode.create(InodeMode::IFDIR, &name).await?;
    Ok(0)
}

pub async fn sys_unlinkat(dirfd: FdNum, path: usize, flags: u32) -> SyscallResult<usize> {
    if flags & !AT_REMOVEDIR != 0 {
        return Err(Errno::EINVAL);
    }
    let mut path = current_process().inner.lock()
        .addr_space.transmute_str(path, PATH_MAX)?.unwrap_or(".");
    debug!("[unlinkat] dirfd: {}, path: {:?}, flags: {:?}", dirfd, path, flags);

    // TODO: This hack is just for libctest
    if path == "/dev/shm/testshm" {
        path = "/tmp/testshm";
    }

    let (parent, name) = split_last_path(path).ok_or(Errno::EINVAL)?;
    let parent = resolve_path(dirfd, &parent, true).await?;
    let inode = parent.clone().lookup_name(&name).await?;
    if inode.metadata().mode == InodeMode::IFDIR {
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
    parent.unlink(&name).await?;
    Ok(0)
}

pub async fn sys_symlinkat(target: usize, dirfd: FdNum, linkpath: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let target = proc_inner.addr_space.transmute_str(target, PATH_MAX)?.ok_or(Errno::EINVAL)?;
    let linkpath = proc_inner.addr_space.transmute_str(linkpath, PATH_MAX)?.ok_or(Errno::EINVAL)?;
    drop(proc_inner);
    debug!("[symlinkat] target: {}, dirfd: {}, linkpath: {}", target, dirfd, linkpath);
    let (parent, name) = split_last_path(linkpath).ok_or(Errno::EINVAL)?;
    let inode = resolve_path(dirfd, &parent, true).await?;
    if inode.metadata().mode != InodeMode::IFDIR {
        return Err(Errno::ENOTDIR);
    }
    inode.symlink(&name, target).await?;
    Ok(0)
}

pub async fn sys_umount2(target: usize, flags: u32) -> SyscallResult<usize> {
    warn!("umount2 is not implemented");
    Ok(0)
}

pub async fn sys_mount(source: usize, target: usize, fstype: usize, flags: u32, data: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let source = proc_inner.addr_space.user_slice_r(VirtAddr(source), PATH_MAX)?;
    let source = CStr::from_bytes_until_nul(source).map_err(|_| Errno::EINVAL)?.to_str().unwrap();
    let target = proc_inner.addr_space.user_slice_r(VirtAddr(target), PATH_MAX)?;
    let target = CStr::from_bytes_until_nul(target).map_err(|_| Errno::EINVAL)?.to_str().unwrap();
    let fstype = proc_inner.addr_space.user_slice_r(VirtAddr(fstype), PATH_MAX)?;
    let fstype = CStr::from_bytes_until_nul(fstype).map_err(|_| Errno::EINVAL)?.to_str().unwrap();
    let flags = VfsFlags::from_bits(flags).ok_or(Errno::EINVAL)?;
    let data = match data {
        0 => None,
        _ => {
            let data = proc_inner.addr_space.user_slice_r(VirtAddr(data), size_of::<usize>())?;
            Some(CStr::from_bytes_until_nul(data).map_err(|_| Errno::EINVAL)?.to_str().unwrap())
        }
    };
    info!(
        "[mount] source: {}, target: {}, fstype: {}, flags: {:?}, data: {:?}",
        source, target, fstype, flags, data,
    );

    match fstype {
        "devfs" => {
            proc_inner.mnt_ns.mount(target, |p| {
                DevFileSystem::new(flags, Some(p))
            }).await?;
        }
        "procfs" => {
            proc_inner.mnt_ns.mount(target, |p| {
                ProcFileSystem::new(flags, Some(p))
            }).await?;
        }
        "tmpfs" => {
            proc_inner.mnt_ns.mount(target, |p| {
                TmpFileSystem::new(flags, Some(p))
            }).await?;
        }
        _ => return Err(Errno::ENODEV),
    }

    Ok(0)
}

pub async fn sys_statfs(path: usize, buf: usize) -> SyscallResult<usize> {
    let path = current_process().inner.lock()
        .addr_space.transmute_str(path, PATH_MAX)?.ok_or(Errno::EINVAL)?;
    let inode = resolve_path(AT_FDCWD, path, true).await?;

    let fs = inode.file_system().upgrade().ok_or(Errno::ENODEV)?;
    let mut stat = KernelStatfs::default();
    stat.f_type = fs.metadata().fstype as u64;
    stat.f_bsize = 512; // TODO: real data
    stat.f_blocks = 1 << 27;
    stat.f_bfree = 1 << 26;
    stat.f_bavail = 1 << 20;
    stat.f_files = 1 << 10;
    stat.f_ffree = 1 << 9;
    stat.f_fsid = 0;
    stat.f_namelen = MAX_NAME_LEN as u64;
    stat.f_frsize = 512;
    stat.f_flags = fs.metadata().flags.bits() as u64;

    let user_buf = current_process().inner.lock()
        .addr_space.user_slice_w(VirtAddr(buf), size_of::<KernelStatfs>())?;
    user_buf.copy_from_slice(&stat.as_bytes());
    Ok(0)
}

pub fn sys_fstatfs(fd: FdNum, buf: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let fd_impl = proc_inner.fd_table.get(fd)?;
    let inode = fd_impl.file.metadata().inode.clone().ok_or(Errno::ENOENT)?;
    let fs = inode.file_system().upgrade().ok_or(Errno::ENODEV)?;
    let user_buf = proc_inner.addr_space.user_slice_w(VirtAddr(buf), size_of::<KernelStatfs>())?;
    let mut stat = KernelStatfs::default();
    stat.f_type = fs.metadata().fstype as u64;
    stat.f_bsize = 512; // TODO: real data
    stat.f_blocks = 1 << 27;
    stat.f_bfree = 1 << 26;
    stat.f_bavail = 1 << 20;
    stat.f_files = 1 << 10;
    stat.f_ffree = 1 << 9;
    stat.f_fsid = 0;
    stat.f_namelen = MAX_NAME_LEN as u64;
    stat.f_frsize = 512;
    stat.f_flags = fs.metadata().flags.bits() as u64;
    user_buf.copy_from_slice(&stat.as_bytes());
    Ok(0)
}

#[suspend]
pub async fn sys_ftruncate(fd: FdNum, size: isize) -> SyscallResult<usize> {
    let fd_impl = current_process().inner.lock().fd_table.get(fd)?;
    if !fd_impl.file.metadata().flags.lock().writable() {
        return Err(Errno::EBADF);
    }
    fd_impl.file.truncate(size).await?;
    Ok(0)
}

pub async fn sys_faccessat(fd: FdNum, path: usize, _mode: u32, _flags: u32) -> SyscallResult<usize> {
    let path = current_process().inner.lock()
        .addr_space.transmute_str(path, PATH_MAX)?.unwrap_or(".");
    resolve_path(fd, path, false).await?;
    Ok(0)
}

pub async fn sys_chdir(path: usize) -> SyscallResult<usize> {
    let path = current_process().inner.lock()
        .addr_space.transmute_str(path, PATH_MAX)?.ok_or(Errno::EINVAL)?;
    resolve_path(AT_FDCWD, path, true).await?;
    current_process().inner.lock().cwd = path.to_string();
    Ok(0)
}

pub async fn sys_openat(dirfd: FdNum, path: usize, flags: u32, _mode: u32) -> SyscallResult<usize> {
    let flags = OpenFlags::from_bits(flags).ok_or(Errno::EINVAL)?;
    let mut path = current_process().inner.lock()
        .addr_space.transmute_str(path, PATH_MAX)?.unwrap_or(".");
    debug!("[openat] dirfd: {}, path: {:?}, flags: {:?}", dirfd, path, flags);

    // TODO: This hack is just for libctest
    if path == "/dev/shm/testshm" {
        path = "/tmp/testshm";
    }

    let inode = match resolve_path(dirfd, path, true).await {
        Ok(inode) => inode,
        Err(Errno::ENOENT) if flags.contains(OpenFlags::O_CREAT) => {
            let (parent, name) = split_last_path(path).ok_or(Errno::EISDIR)?;
            let parent_inode = resolve_path(dirfd, &parent, true).await?;
            parent_inode.create(InodeMode::IFREG, &name).await?
        }
        Err(e) => return Err(e),
    };
    let file = inode.clone().open(flags - OpenFlags::O_CLOEXEC)?;
    if inode.metadata().mode == InodeMode::IFREG {
        if flags.contains(OpenFlags::O_TRUNC) {
            file.truncate(0).await?;
        }
        if flags.contains(OpenFlags::O_APPEND) {
            file.seek(Seek::End(0)).await?;
        }
    }
    let fd_impl = FileDescriptor::new(file, flags.contains(OpenFlags::O_CLOEXEC));
    let fd = current_process().inner.lock().fd_table.put(fd_impl, 0)?;
    Ok(fd as usize)
}

pub fn sys_close(fd: FdNum) -> SyscallResult<usize> {
    let mut proc_inner = current_process().inner.lock();
    proc_inner.fd_table.remove(fd)?;
    Ok(0)
}

pub fn sys_pipe2(fds: usize, flags: u32) -> SyscallResult<usize> {
    let flags = OpenFlags::from_bits(flags).ok_or(Errno::EINVAL)?;
    let mut proc_inner = current_process().inner.lock();
    let user_fds = proc_inner.addr_space.user_slice_w(VirtAddr(fds), size_of::<[FdNum; 2]>())?;
    let (reader, writer) = Pipe::new();
    let reader_fd = proc_inner.fd_table.put(FileDescriptor::new(reader, flags.contains(OpenFlags::O_CLOEXEC)), 0)?;
    let writer_fd = proc_inner.fd_table.put(FileDescriptor::new(writer, flags.contains(OpenFlags::O_CLOEXEC)), 0)?;
    drop(proc_inner);
    user_fds.copy_from_slice(AsBytes::as_bytes(&[reader_fd, writer_fd]));
    Ok(0)
}

pub async fn sys_getdents(fd: FdNum, buf: usize, count: u32) -> SyscallResult<usize> {
    let file = current_process().inner.lock().fd_table.get(fd)?.file;
    let inode = file.metadata().inode.clone().ok_or(Errno::ENOENT)?;
    if inode.metadata().mode != InodeMode::IFDIR {
        return Err(Errno::ENOTDIR);
    }
    let mut cur = buf;
    while let Some((idx, child)) = file.readdir().await? {
        let name = match idx {
            0 => CString::new(".").unwrap(),
            1 => CString::new("..").unwrap(),
            _ => CString::new(child.metadata().name.as_str()).unwrap(),
        };
        let name_bytes = name.as_bytes_with_nul();
        let dirent_size = MAX_DIRENT_SIZE - (MAX_NAME_LEN - name_bytes.len());
        if cur + dirent_size > buf + count as usize {
            break;
        }
        let mut dirent: LinuxDirent = FromZeroes::new_zeroed();
        dirent.d_ino = child.metadata().ino as u64;
        dirent.d_reclen = dirent_size as u16;
        dirent.d_type = DirentType::from(child.metadata().mode).bits();
        dirent.d_name[..name_bytes.len()].copy_from_slice(name_bytes);
        let user_buf = current_process().inner.lock().addr_space.user_slice_w(VirtAddr(cur), dirent_size)?;
        user_buf.copy_from_slice(&dirent.as_bytes()[..dirent_size]);
        cur += dirent_size;
    }
    Ok(cur - buf)
}

#[suspend]
pub async fn sys_lseek(fd: FdNum, offset: isize, whence: i32) -> SyscallResult<usize> {
    let fd_impl = current_process().inner.lock().fd_table.get(fd)?;
    let seek = Seek::try_from((whence, offset))?;
    let ret = fd_impl.file.seek(seek).await?;
    Ok(ret as usize)
}

#[suspend]
pub async fn sys_read(fd: FdNum, buf: usize, len: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let fd_impl = proc_inner.fd_table.get(fd)?;
    if !fd_impl.file.metadata().flags.lock().readable() {
        return Err(Errno::EBADF);
    }
    let user_buf = proc_inner.addr_space.user_slice_w(VirtAddr(buf), len)?;
    drop(proc_inner);
    let ret = fd_impl.file.read(user_buf).await?;
    Ok(ret as usize)
}

#[suspend]
pub async fn sys_write(fd: FdNum, buf: usize, len: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let fd_impl = proc_inner.fd_table.get(fd)?;
    if !fd_impl.file.metadata().flags.lock().writable() {
        return Err(Errno::EBADF);
    }
    let user_buf = proc_inner.addr_space.user_slice_r(VirtAddr(buf), len)?;
    drop(proc_inner);
    let ret = fd_impl.file.write(user_buf).await?;
    Ok(ret as usize)
}

#[suspend]
pub async fn sys_readv(fd: FdNum, iov: usize, iovcnt: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let fd_impl = proc_inner.fd_table.get(fd)?;
    if !fd_impl.file.metadata().flags.lock().readable() {
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

#[suspend]
pub async fn sys_writev(fd: FdNum, iov: usize, iovcnt: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let fd_impl = proc_inner.fd_table.get(fd)?;
    if !fd_impl.file.metadata().flags.lock().writable() {
        return Err(Errno::EPERM);
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

#[suspend]
pub async fn sys_pread(fd: FdNum, buf: usize, len: usize, offset: isize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let fd_impl = proc_inner.fd_table.get(fd)?;
    if !fd_impl.file.metadata().flags.lock().readable() {
        return Err(Errno::EBADF);
    }
    let user_buf = proc_inner.addr_space.user_slice_w(VirtAddr(buf), len)?;
    drop(proc_inner);
    let ret = fd_impl.file.pread(user_buf, offset).await?;
    Ok(ret as usize)
}

#[suspend]
pub async fn sys_pwrite(fd: FdNum, buf: usize, len: usize, offset: isize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let fd_impl = proc_inner.fd_table.get(fd)?;
    if !fd_impl.file.metadata().flags.lock().writable() {
        return Err(Errno::EBADF);
    }
    let user_buf = proc_inner.addr_space.user_slice_r(VirtAddr(buf), len)?;
    drop(proc_inner);
    let ret = fd_impl.file.pwrite(user_buf, offset).await?;
    Ok(ret as usize)
}

#[suspend]
pub async fn sys_sendfile(out_fd: FdNum, in_fd: FdNum, offset: usize, count: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let out_fd_impl = proc_inner.fd_table.get(out_fd)?;
    let in_fd_impl = proc_inner.fd_table.get(in_fd)?;
    let out_flags = out_fd_impl.file.metadata().flags.lock();
    let in_flags = in_fd_impl.file.metadata().flags.lock();
    if !out_flags.writable() || !in_flags.readable() {
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

pub async fn sys_ppoll(ufds: usize, nfds: usize, timeout: usize, sigmask: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let slice = proc_inner.addr_space.user_slice_w(VirtAddr(ufds), size_of::<PollFd>() * nfds)?;
    let fds = PollFd::slice_from(slice).unwrap().to_vec();
    let timeout = proc_inner.addr_space.transmute_r::<TimeSpec>(timeout)?.cloned().map(Duration::from);
    let sigmask = proc_inner.addr_space.transmute_r::<SigSet>(sigmask)?.cloned();
    drop(proc_inner);
    debug!("[ppoll] fds: {:?}, timeout: {:?}, sigmask: {:?}", fds, timeout, sigmask);

    let mask_bak = current_thread().signals.get_mask();
    if let Some(sigmask) = sigmask {
        current_thread().signals.set_mask(sigmask);
    }
    let fut = IOMultiplexFuture::new(fds, IOFormat::PollFds(ufds));
    let ret = match suspend_now(timeout, Event::all(), fut).await {
        Err(Errno::ETIMEDOUT) => {
            debug!("[ppoll] timeout");
            Ok(0)
        }
        other => other,
    };
    current_thread().signals.set_mask(mask_bak);
    ret
}

pub async fn sys_pselect6(nfds: FdNum, readfds: usize, writefds: usize, exceptfds: usize, timeout: usize, sigmask: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let rfds = proc_inner.addr_space.transmute_w::<FdSet>(readfds)?;
    let wfds = proc_inner.addr_space.transmute_w::<FdSet>(writefds)?;
    let efds = proc_inner.addr_space.transmute_w::<FdSet>(exceptfds)?;
    let timeout = proc_inner.addr_space.transmute_r::<TimeVal>(timeout)?.cloned().map(Duration::from);
    let sigmask = proc_inner.addr_space.transmute_r::<SigSet>(sigmask)?.cloned();
    debug!(
        "[sys_pselect]: readfds {:?}, writefds {:?}, exceptfds {:?}, timeout {:?}, sigmask {:?}",
        rfds, wfds, efds, timeout, sigmask,
    );
    let fd_slot_bits = 8 * size_of::<usize>();
    let mut fds: Vec<PollFd> = Vec::new();
    for fd_slot in 0..FD_SET_LEN {
        for offset in 0..fd_slot_bits {
            let fd = fd_slot * fd_slot_bits + offset;
            if fd >= nfds as usize {
                break;
            }
            if let Some(readfds) = rfds.as_ref() {
                if readfds.fds_bits[fd_slot] & (1 << offset) != 0 {
                    if !proc_inner.fd_table.get(fd as FdNum).is_ok() {
                        warn!("[sys_pselect] bad fd {}", fd);
                        return Err(Errno::EBADF);
                    }

                    fds.push(PollFd {
                        fd: fd as i32,
                        events: PollEvents::POLLIN,
                        revents: PollEvents::empty(),
                    })
                }
            }
            if let Some(writefds) = wfds.as_ref() {
                if writefds.fds_bits[fd_slot] & (1 << offset) != 0 {
                    if let Some(old_fd) = fds.last() {
                        if old_fd.fd == fd as i32 {
                            let events = old_fd.events | PollEvents::POLLOUT;
                            fds.last_mut().unwrap().events = events;
                        }
                    } else {
                        if !proc_inner.fd_table.get(fd as FdNum).is_ok() {
                            warn!("[sys_pselect] bad fd {}", fd);
                            return Err(Errno::EBADF);
                        }
                        fds.push(PollFd {
                            fd: fd as i32,
                            events: PollEvents::POLLOUT,
                            revents: PollEvents::empty(),
                        })
                    }
                }
            }
            if let Some(exceptfds) = efds.as_ref() {
                if exceptfds.fds_bits[fd_slot] & (1 << offset) != 0 {
                    if let Some(old_fd) = fds.last() {
                        if old_fd.fd == fd as i32 {
                            let events = old_fd.events | PollEvents::POLLPRI;
                            fds.last_mut().unwrap().events = events;
                        }
                    } else {
                        if !proc_inner.fd_table.get(fd as FdNum).is_ok() {
                            warn!("[sys_pselect] bad fd {}", fd);
                            return Err(Errno::EBADF);
                        }
                        fds.push(PollFd {
                            fd: fd as i32,
                            events: PollEvents::POLLPRI,
                            revents: PollEvents::empty(),
                        })
                    }
                }
            }
        }
    }
    if let Some(fds) = rfds {
        fds.fds_bits.fill(0);
    }
    if let Some(fds) = wfds {
        fds.fds_bits.fill(0);
    }
    if let Some(fds) = efds {
        fds.fds_bits.fill(0);
    }
    drop(proc_inner);
    let mask_bak = current_thread().signals.get_mask();
    if let Some(sigmask) = sigmask {
        current_thread().signals.set_mask(sigmask);
    }
    let fut = IOMultiplexFuture::new(fds, IOFormat::FdSets(FdSetRWE::new(readfds, writefds, exceptfds)));
    let ret = match suspend_now(timeout, Event::all(), fut).await {
        Err(Errno::ETIMEDOUT) => {
            debug!("[pselect] timeout");
            Ok(0)
        }
        other => other,
    };
    current_thread().signals.set_mask(mask_bak);
    ret
}

pub async fn sys_readlinkat(dirfd: FdNum, path: usize, buf: usize, bufsiz: usize) -> SyscallResult<usize> {
    let path = current_process().inner.lock()
        .addr_space.transmute_str(path, PATH_MAX)?.unwrap_or(".");
    let inode = resolve_path(dirfd, path, false).await?;
    if inode.metadata().mode != InodeMode::IFLNK {
        return Err(Errno::EINVAL);
    }
    let target = inode.readlink().await?.into_bytes();
    let user_buf = current_process().inner.lock()
        .addr_space.user_slice_w(VirtAddr(buf), min(target.len(), bufsiz))?;
    user_buf[..target.len()].copy_from_slice(&target);
    Ok(target.len())
}

pub async fn sys_newfstatat(dirfd: FdNum, path: usize, buf: usize, flags: u32) -> SyscallResult<usize> {
    let path = current_process().inner.lock()
        .addr_space.transmute_str(path, PATH_MAX)?.unwrap_or(".");
    let follow_link = flags & AT_SYMLINK_NOFOLLOW == 0;
    let inode = resolve_path(dirfd, path, follow_link).await?;
    let user_buf = current_process().inner.lock()
        .addr_space.user_slice_w(VirtAddr(buf), size_of::<KernelStat>())?;
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
    } else {
        stat.st_mode = InodeMode::IFCHR as u32;
    }
    user_buf.copy_from_slice(stat.as_bytes());
    Ok(0)
}

pub async fn sys_fsync(fd: FdNum) -> SyscallResult<usize> {
    let fd_impl = current_process().inner.lock().fd_table.get(fd)?;
    fd_impl.file.sync().await?;
    Ok(0)
}

#[suspend]
pub async fn sys_utimensat(dirfd: FdNum, path: usize, times: usize, flags: u32) -> SyscallResult<usize> {
    let path = current_process().inner.lock()
        .addr_space.transmute_str(path, PATH_MAX)?.unwrap_or(".");
    let follow_link = flags & AT_SYMLINK_NOFOLLOW == 0;
    let inode = resolve_path(dirfd, path, follow_link).await?;
    let now = TimeSpec::from(real_time());
    let (atime, mtime) = match times {
        0 => (Some(now), Some(now)),
        _ => {
            let times = current_process().inner.lock()
                .addr_space.user_slice_r(VirtAddr(times), 2 * size_of::<TimeSpec>())?;
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
    inode.metadata().inner.lock().tap_mut(|inner| {
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

pub async fn sys_renameat2(old_dirfd: FdNum, old_path: usize, new_dirfd: FdNum, new_path: usize, flags: u32) -> SyscallResult<usize> {
    let flags = RenameFlags::from_bits(flags).ok_or(Errno::EINVAL)?;
    let proc_inner = current_process().inner.lock();
    let old_path = proc_inner.addr_space.transmute_str(old_path, PATH_MAX)?.unwrap_or(".");
    let new_path = proc_inner.addr_space.transmute_str(new_path, PATH_MAX)?.unwrap_or(".");
    drop(proc_inner);
    debug!(
        "[renameat] old_dirfd: {}, old_path: {:?}, new_dirfd: {}, new_path: {:?}, flags: {:?}",
        old_dirfd, old_path, new_dirfd, new_path, flags,
    );
    let (old_parent, old_name) = split_last_path(old_path).ok_or(Errno::EINVAL)?;
    let (new_parent, new_name) = split_last_path(new_path).ok_or(Errno::EINVAL)?;
    let old_parent = resolve_path(old_dirfd, &old_parent, true).await?;
    let new_parent = resolve_path(new_dirfd, &new_parent, true).await?;
    let old_inode = old_parent.clone().lookup_name(&old_name).await?;
    let new_inode = new_parent.clone().lookup_name(&new_name).await;
    match flags {
        RenameFlags::RENAME_DEFAULT => {
            if new_inode.is_ok() {
                new_parent.clone().unlink(&new_name).await?;
            }
            // old_parent.unlink(&old_name).await?;
            new_parent.movein(&new_name, old_inode).await?;
        }
        RenameFlags::RENAME_NOREPLACE => {
            if new_inode.is_ok() {
                return Err(Errno::EEXIST);
            }
            // old_parent.unlink(&old_name).await?;
            new_parent.movein(&new_name, old_inode).await?;
        }
        RenameFlags::RENAME_EXCHANGE => {
            let new_inode = new_inode?;
            // old_parent.clone().unlink(&old_name).await?;
            // new_parent.clone().unlink(&new_name).await?;
            old_parent.movein(&new_name, new_inode).await?;
            new_parent.movein(&old_name, old_inode).await?;
        }
        _ => {
            warn!("[renameat] Invalid flags: {:?}", flags);
            return Err(Errno::EINVAL);
        }
    }
    Ok(0)
}
