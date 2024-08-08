use alloc::ffi::CString;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;
use core::mem::size_of;
use core::time::Duration;
use log::{debug, info, warn};
use tap::Tap;
use zerocopy::{AsBytes, FromBytes, FromZeroes};
use macros::suspend;
use crate::arch::PAGE_SIZE;
use crate::fs::fd::{FdNum, FileDescriptor};
use crate::fs::ffi::{AT_FDCWD, AT_REMOVEDIR, MAX_DIRENT_SIZE, DirentType, FcntlCmd, InodeMode, IoVec, KernelStat, LinuxDirent, MAX_NAME_LEN, OpenFlags, PATH_MAX, RenameFlags, PollFd, VfsFlags, FdSet, FD_SET_LEN, PollEvents, KernelStatfs, AT_SYMLINK_NOFOLLOW, AccessMode};
use crate::fs::file::Seek;
use crate::fs::path::{resolve_path, split_last_path};
use crate::fs::pipe::Pipe;
use crate::mm::protect::{user_slice_r, user_slice_w, user_transmute_r, user_transmute_str, user_transmute_w};
use crate::process::thread::event_bus::Event;
use crate::process::{Gid, Uid};
use crate::processor::{current_process, current_thread};
use crate::result::{Errno, SyscallResult};
use crate::sched::ffi::{TimeSpec, UTIME_NOW, UTIME_OMIT};
use crate::sched::iomultiplex::{FdSetRWE, IOFormat, IOMultiplexFuture};
use crate::sched::suspend_now;
use crate::sched::time::real_time;
use crate::signal::ffi::SigSet;

pub fn sys_getcwd(buf: usize, size: usize) -> SyscallResult<usize> {
    if size == 0 {
        return Err(Errno::ERANGE);
    }
    if buf == 0 && size > 1 {
        return Err(Errno::EFAULT);
    }
    let cwd = current_process().inner.lock().cwd.clone();
    if cwd.len() + 1 > size {
        return Err(Errno::ERANGE);
    }
    let user_buf = user_slice_w(buf, size)?;
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
    let mode = match mode {
        0 => InodeMode::def_dir() - current_process().inner.lock().umask,
        _ => InodeMode::from_bits_access(mode).ok_or(Errno::EINVAL)? | InodeMode::S_IFDIR,
    };
    let path = user_transmute_str(path, PATH_MAX)?.ok_or(Errno::EINVAL)?;
    debug!("[mkdirat] fd: {}, path: {:?}, mode: {}", dirfd, path, mode);
    let (parent, name) = split_last_path(path).ok_or(Errno::EEXIST)?;
    let token = current_thread().token();
    let inode = resolve_path(dirfd, &parent, true, token).await?;
    inode.create(mode, &name, token).await?;
    Ok(0)
}

pub async fn sys_unlinkat(dirfd: FdNum, path: usize, flags: u32) -> SyscallResult<usize> {
    if flags & !AT_REMOVEDIR != 0 {
        return Err(Errno::EINVAL);
    }
    let mut path = user_transmute_str(path, PATH_MAX)?.unwrap_or(".");
    debug!("[unlinkat] dirfd: {}, path: {:?}, flags: {:?}", dirfd, path, flags);

    // TODO: This hack is just for libctest
    if path == "/dev/shm/testshm" {
        path = "/tmp/testshm";
    }

    let (parent, name) = split_last_path(path).ok_or(Errno::EINVAL)?;
    let token = current_thread().token();
    let parent = resolve_path(dirfd, &parent, true, token).await?;
    let inode = parent.clone().lookup_name(&name, token).await?;
    if inode.metadata().ifmt.is_dir() {
        if flags & AT_REMOVEDIR == 0 {
            return Err(Errno::EISDIR);
        }
        if inode.clone().lookup_idx(0, token).await.is_ok() {
            return Err(Errno::ENOTEMPTY);
        }
    } else {
        if flags & AT_REMOVEDIR != 0 {
            return Err(Errno::ENOTDIR);
        }
    }
    parent.unlink(&name, token).await?;
    Ok(0)
}

pub async fn sys_symlinkat(target: usize, dirfd: FdNum, linkpath: usize) -> SyscallResult<usize> {
    let target = user_transmute_str(target, PATH_MAX)?.ok_or(Errno::EINVAL)?;
    let linkpath = user_transmute_str(linkpath, PATH_MAX)?.ok_or(Errno::EINVAL)?;
    debug!("[symlinkat] target: {}, dirfd: {}, linkpath: {}", target, dirfd, linkpath);
    let (parent, name) = split_last_path(linkpath).ok_or(Errno::EINVAL)?;
    let token = current_thread().token();
    let inode = resolve_path(dirfd, &parent, true, token).await?;
    if !inode.metadata().ifmt.is_dir() {
        return Err(Errno::ENOTDIR);
    }
    inode.symlink(InodeMode::def_lnk(), &name, target, token).await?;
    Ok(0)
}

pub async fn sys_umount2(target: usize, flags: u32) -> SyscallResult<usize> {
    let target = user_transmute_str(target, PATH_MAX)?.ok_or(Errno::EINVAL)?;
    debug!("[umount2] target: {}, flags: {:#x}", target, flags);
    let token = current_thread().token();
    let mnt_ns = current_process().inner.lock().mnt_ns.clone();
    let target = resolve_path(AT_FDCWD, target, true, token).await?;
    if !target.metadata().ifmt.is_dir() {
        return Err(Errno::ENOTDIR);
    }
    mnt_ns.unmount(target)?;
    Ok(0)
}

pub async fn sys_mount(source: usize, target: usize, fstype: usize, flags: u32, data: usize) -> SyscallResult<usize> {
    let source = user_transmute_str(source, PATH_MAX)?;
    let target = user_transmute_str(target, PATH_MAX)?.ok_or(Errno::EINVAL)?;
    let fstype = user_transmute_str(fstype, PATH_MAX)?.ok_or(Errno::EINVAL)?;
    let flags = VfsFlags::from_bits_truncate(flags);
    let data = user_transmute_str(data, PATH_MAX)?;
    info!(
        "[mount] source: {:?}, target: {}, fstype: {}, flags: {:?}, data: {:?}",
        source, target, fstype, flags, data,
    );

    let token = current_thread().token();
    let mnt_ns = current_process().inner.lock().mnt_ns.clone();
    let target = resolve_path(AT_FDCWD, target, true, token).await?;
    if !target.metadata().ifmt.is_dir() {
        return Err(Errno::ENOTDIR);
    }
    mnt_ns.mount(source, target, fstype, flags)?;
    Ok(0)
}

pub async fn sys_statfs(path: usize, buf: usize) -> SyscallResult<usize> {
    let path = user_transmute_str(path, PATH_MAX)?.ok_or(Errno::EINVAL)?;
    let writeback = user_transmute_w(buf)?.ok_or(Errno::EINVAL)?;
    let token = current_thread().token();
    let inode = resolve_path(AT_FDCWD, path, true, token).await?;
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
    stat.f_flags = fs.flags().bits() as u64;
    *writeback = stat;
    Ok(0)
}

pub fn sys_fstatfs(fd: FdNum, buf: usize) -> SyscallResult<usize> {
    let fd_impl = current_process().inner.lock().fd_table.get(fd)?;
    let writeback = user_transmute_w(buf)?.ok_or(Errno::EINVAL)?;
    let inode = fd_impl.file.metadata().inode.clone().ok_or(Errno::ENOENT)?;
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
    stat.f_flags = fs.flags().bits() as u64;
    *writeback = stat;
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

pub async fn sys_faccessat(fd: FdNum, path: usize, mode: u32) -> SyscallResult<usize> {
    let mode = AccessMode::from_bits(mode).ok_or(Errno::EINVAL)?;
    let path = user_transmute_str(path, PATH_MAX)?.unwrap_or(".");
    let token = current_thread().token();
    let inode = resolve_path(fd, path, true, token).await?;
    inode.proc_access(token, mode)?;
    Ok(0)
}

pub async fn sys_chdir(path: usize) -> SyscallResult<usize> {
    let path = user_transmute_str(path, PATH_MAX)?.ok_or(Errno::EINVAL)?;
    let token = current_thread().token();
    let inode = resolve_path(AT_FDCWD, path, true, token).await?;
    if inode.metadata().ifmt != InodeMode::S_IFDIR {
        return Err(Errno::ENOTDIR);
    }
    let mut proc_inner = current_process().inner.lock();
    proc_inner.cwd = inode.mnt_ns_path(&proc_inner.mnt_ns)?;
    Ok(0)
}

pub async fn sys_fchmodat(dirfd: FdNum, path: usize, mode: u32, flags: u32) -> SyscallResult<usize> {
    // TODO: Permission check
    let mode = InodeMode::from_bits_access(mode).ok_or(Errno::EINVAL)?;
    let path = user_transmute_str(path, PATH_MAX)?.ok_or(Errno::EINVAL)?;
    let follow_link = flags & AT_SYMLINK_NOFOLLOW == 0;
    let token = current_thread().token();
    let inode = resolve_path(dirfd, path, follow_link, token).await?;
    inode.chmod(mode);
    Ok(0)
}

pub async fn sys_fchownat(dirfd: FdNum, path: usize, uid: Uid, gid: Gid, flags: u32) -> SyscallResult<usize> {
    // TODO: Permission check
    let path = user_transmute_str(path, PATH_MAX)?.ok_or(Errno::EINVAL)?;
    let follow_link = flags & AT_SYMLINK_NOFOLLOW == 0;
    let token = current_thread().token();
    let inode = resolve_path(dirfd, path, follow_link, token).await?;
    inode.metadata().inner.lock().uid = uid;
    inode.metadata().inner.lock().gid = gid;
    Ok(0)
}

pub async fn sys_openat(dirfd: FdNum, path: usize, flags: u32, mode: u32) -> SyscallResult<usize> {
    let flags = OpenFlags::from_bits(flags).ok_or(Errno::EINVAL)?;
    let mut path = user_transmute_str(path, PATH_MAX)?.unwrap_or(".");
    debug!("[openat] dirfd: {}, path: {:?}, flags: {:?}, mode: {:o}", dirfd, path, flags, mode);

    // TODO: This hack is just for libctest
    if path == "/dev/shm/testshm" {
        path = "/tmp/testshm";
    }

    let token = current_thread().token();
    let inode = match resolve_path(dirfd, path, true, token).await {
        Ok(inode) => inode,
        Err(Errno::ENOENT) if flags.contains(OpenFlags::O_CREAT) => {
            let mode = match mode {
                0 => InodeMode::def_file() - current_process().inner.lock().umask,
                _ => InodeMode::from_bits_access(mode).ok_or(Errno::EINVAL)? | InodeMode::S_IFREG,
            };
            let (parent, name) = split_last_path(path).ok_or(Errno::EISDIR)?;
            let parent_inode = resolve_path(dirfd, &parent, true, token).await?;
            parent_inode.create(mode, &name, token).await?
        }
        Err(e) => return Err(e),
    };
    let file = inode.clone().open(flags - OpenFlags::O_CLOEXEC, token)?;
    if inode.metadata().ifmt == InodeMode::S_IFREG {
        if flags.contains(OpenFlags::O_DIRECTORY) {
            return Err(Errno::ENOTDIR);
        }
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
    let fds = user_slice_w(fds, size_of::<[FdNum; 2]>())?;
    let (reader, writer) = Pipe::new();
    let mut proc_inner = current_process().inner.lock();
    let reader_fd = proc_inner.fd_table.put(FileDescriptor::new(reader, flags.contains(OpenFlags::O_CLOEXEC)), 0)?;
    let writer_fd = proc_inner.fd_table.put(FileDescriptor::new(writer, flags.contains(OpenFlags::O_CLOEXEC)), 0)?;
    fds.copy_from_slice(AsBytes::as_bytes(&[reader_fd, writer_fd]));
    Ok(0)
}

pub async fn sys_getdents(fd: FdNum, buf: usize, count: u32) -> SyscallResult<usize> {
    if count <= 1 {
        return Err(Errno::EINVAL);
    }
    let file = current_process().inner.lock().fd_table.get(fd)?.file;
    let inode = file.metadata().inode.clone().ok_or(Errno::ENOENT)?;
    if inode.metadata().ifmt != InodeMode::S_IFDIR {
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
        dirent.d_type = DirentType::from(child.metadata().ifmt).bits();
        dirent.d_name[..name_bytes.len()].copy_from_slice(name_bytes);
        let user_buf = user_slice_w(cur, dirent_size)?;
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
    let fd_impl = current_process().inner.lock().fd_table.get(fd)?;
    if !fd_impl.file.metadata().flags.lock().readable() {
        return Err(Errno::EBADF);
    }
    let buf = user_slice_w(buf, len)?;
    let ret = fd_impl.file.read(buf).await?;
    Ok(ret as usize)
}

#[suspend]
pub async fn sys_write(fd: FdNum, buf: usize, len: usize) -> SyscallResult<usize> {
    let fd_impl = current_process().inner.lock().fd_table.get(fd)?;
    if !fd_impl.file.metadata().flags.lock().writable() {
        return Err(Errno::EBADF);
    }
    let buf = user_slice_r(buf, len)?;
    let ret = fd_impl.file.write(buf).await?;
    Ok(ret as usize)
}

#[suspend]
pub async fn sys_readv(fd: FdNum, iov: usize, iovcnt: usize) -> SyscallResult<usize> {
    let fd_impl = current_process().inner.lock().fd_table.get(fd)?;
    if !fd_impl.file.metadata().flags.lock().readable() {
        return Err(Errno::EBADF);
    }
    let user_buf = user_slice_r(iov, size_of::<IoVec>() * iovcnt)?;
    let iovs: &[IoVec] = unsafe { core::mem::transmute(user_buf) };

    let mut ret = 0;
    for i in 0..iovcnt {
        let iov = &iovs[i];
        let user_buf = user_slice_w(iov.base, iov.len)?;
        ret += fd_impl.file.read(user_buf).await?;
    }
    Ok(ret as usize)
}

#[suspend]
pub async fn sys_writev(fd: FdNum, iov: usize, iovcnt: usize) -> SyscallResult<usize> {
    let fd_impl = current_process().inner.lock().fd_table.get(fd)?;
    if !fd_impl.file.metadata().flags.lock().writable() {
        return Err(Errno::EPERM);
    }
    let user_buf = user_slice_r(iov, size_of::<IoVec>() * iovcnt)?;
    let iovs: &[IoVec] = unsafe { core::mem::transmute(user_buf) };

    let mut ret = 0;
    for i in 0..iovcnt {
        let iov = &iovs[i];
        let user_buf = user_slice_r(iov.base, iov.len)?;
        ret += fd_impl.file.write(user_buf).await?;
    }

    Ok(ret as usize)
}

#[suspend]
pub async fn sys_pread(fd: FdNum, buf: usize, len: usize, offset: isize) -> SyscallResult<usize> {
    let fd_impl = current_process().inner.lock().fd_table.get(fd)?;
    if !fd_impl.file.metadata().flags.lock().readable() {
        return Err(Errno::EBADF);
    }
    let user_buf = user_slice_w(buf, len)?;
    let ret = fd_impl.file.pread(user_buf, offset).await?;
    Ok(ret as usize)
}

#[suspend]
pub async fn sys_pwrite(fd: FdNum, buf: usize, len: usize, offset: isize) -> SyscallResult<usize> {
    let fd_impl = current_process().inner.lock().fd_table.get(fd)?;
    if !fd_impl.file.metadata().flags.lock().writable() {
        return Err(Errno::EBADF);
    }
    let user_buf = user_slice_r(buf, len)?;
    let ret = fd_impl.file.pwrite(user_buf, offset).await?;
    Ok(ret as usize)
}

#[suspend]
pub async fn sys_sendfile(out_fd: FdNum, in_fd: FdNum, offset: usize, count: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let out_fd_impl = proc_inner.fd_table.get(out_fd)?;
    let in_fd_impl = proc_inner.fd_table.get(in_fd)?;
    drop(proc_inner);
    let out_flags = out_fd_impl.file.metadata().flags.lock();
    let in_flags = in_fd_impl.file.metadata().flags.lock();
    if !out_flags.writable() || !in_flags.readable() {
        return Err(Errno::EBADF);
    }
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
        let offset = user_transmute_w::<usize>(offset)?.ok_or(Errno::EINVAL)?;
        let mut sent = 0;
        while sent < count {
            let end = min(count - sent, buf.len());
            let read = in_fd_impl.file.pread(&mut buf[..end], (*offset + sent) as isize).await? as usize;
            if read == 0 {
                break;
            }
            out_fd_impl.file.write(&buf[..read]).await?;
            sent += read;
        }
        *offset += sent;
        Ok(sent)
    }
}

pub async fn sys_ppoll(ufds: usize, nfds: usize, timeout: usize, sigmask: usize) -> SyscallResult<usize> {
    let slice = user_slice_w(ufds, size_of::<PollFd>() * nfds)?;
    let fds = PollFd::slice_from(slice).unwrap().to_vec();
    let timeout = user_transmute_r::<TimeSpec>(timeout)?.cloned().map(Duration::from);
    let sigmask = user_transmute_r::<SigSet>(sigmask)?.cloned();
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
    let rfds = user_transmute_w::<FdSet>(readfds)?;
    let wfds = user_transmute_w::<FdSet>(writefds)?;
    let efds = user_transmute_w::<FdSet>(exceptfds)?;
    let timeout = user_transmute_r::<TimeSpec>(timeout)?.cloned().map(Duration::from);
    let sigmask = user_transmute_r::<SigSet>(sigmask)?.cloned();
    debug!(
        "[sys_pselect]: readfds {:?}, writefds {:?}, exceptfds {:?}, timeout {:?}, sigmask {:?}",
        rfds, wfds, efds, timeout, sigmask,
    );
    let proc_inner = current_process().inner.lock();
    let fd_slot_bits = 8 * size_of::<usize>();
    let mut fds: Vec<PollFd> = Vec::new();
    for fd_slot in 0..FD_SET_LEN {
        for offset in 0..fd_slot_bits {
            let fd = (fd_slot * fd_slot_bits + offset) as FdNum;
            if fd >= nfds {
                break;
            }
            let mut find_and_push = |set: &FdSet, event: PollEvents| {
                if set.fds_bits[fd_slot] & (1 << offset) != 0 {
                    if let Some(old_fd) = fds.last_mut() && fd == old_fd.fd {
                        old_fd.events |= event;
                    } else {
                        proc_inner.fd_table.get(fd)?;
                        fds.push(PollFd {
                            fd,
                            events: event,
                            revents: PollEvents::empty(),
                        });
                    }
                }
                Ok(())
            };
            if let Some(readfds) = rfds.as_ref() {
                find_and_push(readfds, PollEvents::POLLIN)?;
            }
            if let Some(writefds) = wfds.as_ref() {
                find_and_push(writefds, PollEvents::POLLOUT)?;
            }
            if let Some(exceptfds) = efds.as_ref() {
                find_and_push(exceptfds, PollEvents::POLLPRI)?;
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
    let path = user_transmute_str(path, PATH_MAX)?.unwrap_or(".");
    let token = current_thread().token();
    let inode = resolve_path(dirfd, path, false, token).await?;
    if inode.metadata().ifmt != InodeMode::S_IFLNK {
        return Err(Errno::EINVAL);
    }
    let target = inode.readlink(token).await?.into_bytes();
    let buf = user_slice_w(buf, min(target.len(), bufsiz))?;
    buf[..target.len()].copy_from_slice(&target);
    Ok(target.len())
}

pub async fn sys_newfstatat(dirfd: FdNum, path: usize, buf: usize, flags: u32) -> SyscallResult<usize> {
    let path = user_transmute_str(path, PATH_MAX)?.unwrap_or(".");
    let writeback = user_transmute_w(buf)?.ok_or(Errno::EINVAL)?;
    let follow_link = flags & AT_SYMLINK_NOFOLLOW == 0;
    let token = current_thread().token();
    let inode = resolve_path(dirfd, path, follow_link, token).await?;
    let mut stat = KernelStat::default();
    stat.st_dev = inode.metadata().dev;
    stat.st_ino = inode.metadata().ino as u64;
    let inner = inode.metadata().inner.lock();
    stat.st_uid = inner.uid as u32;
    stat.st_mode = inner.mode.bits();
    stat.st_nlink = inner.nlink as u32;
    stat.st_size = inner.size as u64;
    stat.st_atim = inner.atime;
    stat.st_mtim = inner.mtime;
    stat.st_ctim = inner.ctime;
    *writeback = stat;
    Ok(0)
}

pub fn sys_fstat(fd: FdNum, buf: usize) -> SyscallResult<usize> {
    let fd_impl = current_process().inner.lock().fd_table.get(fd)?;
    let writeback = user_transmute_w(buf)?.ok_or(Errno::EINVAL)?;
    let inode = fd_impl.file.metadata().inode.clone();
    let mut stat = KernelStat::default();
    if let Some(inode) = inode {
        stat.st_dev = inode.metadata().dev;
        stat.st_ino = inode.metadata().ino as u64;
        let inner = inode.metadata().inner.lock();
        stat.st_uid = inner.uid as u32;
        stat.st_mode = inner.mode.bits();
        stat.st_nlink = inner.nlink as u32;
        stat.st_size = inner.size as u64;
        stat.st_atim = inner.atime;
        stat.st_mtim = inner.mtime;
        stat.st_ctim = inner.ctime;
    } else {
        stat.st_mode = InodeMode::S_IFCHR.bits();
    }
    *writeback = stat;
    Ok(0)
}

pub async fn sys_fsync(fd: FdNum) -> SyscallResult<usize> {
    let fd_impl = current_process().inner.lock().fd_table.get(fd)?;
    fd_impl.file.sync().await?;
    Ok(0)
}

#[suspend]
pub async fn sys_utimensat(dirfd: FdNum, path: usize, times: usize, flags: u32) -> SyscallResult<usize> {
    let path = user_transmute_str(path, PATH_MAX)?.unwrap_or(".");
    let follow_link = flags & AT_SYMLINK_NOFOLLOW == 0;
    let token = current_thread().token();
    let inode = resolve_path(dirfd, path, follow_link, token).await?;
    let now = TimeSpec::from(real_time());
    let (atime, mtime) = match times {
        0 => (Some(now), Some(now)),
        _ => {
            let times = user_slice_r(times, 2 * size_of::<TimeSpec>())?;
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
    let old_path = user_transmute_str(old_path, PATH_MAX)?.unwrap_or(".");
    let new_path = user_transmute_str(new_path, PATH_MAX)?.unwrap_or(".");
    debug!(
        "[renameat] old_dirfd: {}, old_path: {:?}, new_dirfd: {}, new_path: {:?}, flags: {:?}",
        old_dirfd, old_path, new_dirfd, new_path, flags,
    );
    let (old_parent, old_name) = split_last_path(old_path).ok_or(Errno::EINVAL)?;
    let (new_parent, new_name) = split_last_path(new_path).ok_or(Errno::EINVAL)?;
    let token = current_thread().token();
    let old_parent = resolve_path(old_dirfd, &old_parent, true, token).await?;
    let new_parent = resolve_path(new_dirfd, &new_parent, true, token).await?;
    let old_inode = old_parent.clone().lookup_name(&old_name, token).await?;
    let new_inode = new_parent.clone().lookup_name(&new_name, token).await;
    match flags {
        RenameFlags::RENAME_DEFAULT => {
            if new_inode.is_ok() {
                new_parent.clone().unlink(&new_name, token).await?;
            }
            // old_parent.unlink(&old_name).await?;
            new_parent.movein(&new_name, old_inode, token).await?;
        }
        RenameFlags::RENAME_NOREPLACE => {
            if new_inode.is_ok() {
                return Err(Errno::EEXIST);
            }
            // old_parent.unlink(&old_name).await?;
            new_parent.movein(&new_name, old_inode, token).await?;
        }
        RenameFlags::RENAME_EXCHANGE => {
            let new_inode = new_inode?;
            // old_parent.clone().unlink(&old_name).await?;
            // new_parent.clone().unlink(&new_name).await?;
            old_parent.movein(&new_name, new_inode, token).await?;
            new_parent.movein(&old_name, old_inode, token).await?;
        }
        _ => {
            warn!("[renameat] Invalid flags: {:?}", flags);
            return Err(Errno::EINVAL);
        }
    }
    Ok(0)
}
