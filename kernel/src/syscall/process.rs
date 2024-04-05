use alloc::ffi::CString;
use alloc::vec::Vec;
use core::mem::size_of;
use core::pin::pin;
use futures::future::{Either, select};
use log::{debug, info};
use crate::arch::VirtAddr;
use crate::fs::ffi::{AT_FDCWD, InodeMode, PATH_MAX};
use crate::fs::path::resolve_path;
use crate::process::ffi::{CloneFlags, WaitOptions};
use crate::process::Pid;
use crate::process::thread::wait::{Event, WaitPidFuture};
use crate::processor::{current_process, current_thread};
use crate::result::{Errno, SyscallResult};
use crate::sched::yield_now;

pub fn sys_exit(exit_code: i8) -> SyscallResult<usize> {
    current_thread().terminate(exit_code);
    Ok(0)
}

pub fn sys_set_tid_address(tidptr: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    if proc_inner.addr_space.user_slice_w(VirtAddr(tidptr), size_of::<usize>()).is_ok() {
        current_thread().inner().tid_address.clear_tid_address = Some(tidptr);
    }
    Ok(current_thread().tid.0)
}

pub async fn sys_yield() -> SyscallResult<usize> {
    yield_now().await;
    Ok(0)
}

pub fn sys_getpid() -> SyscallResult<usize> {
    Ok(current_process().pid.0)
}

pub fn sys_getppid() -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    // SAFETY: 由于我们将 init 进程的 parent 设置为自己，所以这里可以直接 unwrap
    Ok(proc_inner.parent.upgrade().unwrap().pid.0)
}

pub fn sys_getuid() -> SyscallResult<usize> {
    // TODO: Real UID support
    Ok(0)
}

pub fn sys_geteuid() -> SyscallResult<usize> {
    // TODO: Real UID support
    Ok(0)
}

pub fn sys_getegid() -> SyscallResult<usize> {
    // TODO: Real UID support
    Ok(0)
}

pub fn sys_gettid() -> SyscallResult<usize> {
    Ok(current_thread().tid.0)
}

pub fn sys_clone(flags: u32, stack: usize, ptid: usize, tls: usize, ctid: usize) -> SyscallResult<usize> {
    let flags = CloneFlags::from_bits(flags).ok_or(Errno::EINVAL)?;
    debug!("[sys_clone] flags: {:?}", flags);
    if flags.contains(CloneFlags::CLONE_VM) {
        current_process().clone_thread(flags, stack, tls, ptid, ctid)
    } else {
        current_process().fork_process(flags, stack)
    }
}

pub async fn sys_execve(path: usize, args: usize, envs: usize) -> SyscallResult<usize> {
    let proc_inner = current_process().inner.lock();
    let mut path = proc_inner.addr_space.user_slice_str(VirtAddr(path), PATH_MAX)?;
    debug!("[sys_execve] path: {:?}", path);

    let mut args_vec: Vec<CString> = Vec::new();
    let mut envs_vec: Vec<CString> = Vec::new();
    if path.ends_with(".sh") {
        path = "/busybox";
        args_vec.push(CString::new("busybox").unwrap());
        args_vec.push(CString::new("sh").unwrap());
    }
    let push_args = |args_vec: &mut Vec<CString>, mut arg_ptr: usize| -> SyscallResult {
        loop {
            proc_inner.addr_space.user_slice_r(VirtAddr(arg_ptr), size_of::<usize>())?;
            let arg_addr = unsafe { *(arg_ptr as *const usize) };
            if arg_addr == 0 { break; }
            let arg = proc_inner.addr_space.user_slice_str(VirtAddr(arg_addr), PATH_MAX)?;
            if arg.is_empty() { break; }
            args_vec.push(CString::new(arg).unwrap());
            arg_ptr += size_of::<usize>();
        }
        Ok(())
    };
    push_args(&mut args_vec, args)?;
    push_args(&mut envs_vec, envs)?;
    if args_vec.is_empty() {
        args_vec.push(CString::new(path).unwrap());
    }
    envs_vec.push(CString::new("PATH=/").unwrap());
    envs_vec.push(CString::new("LD_LIBRARY_PATH=/").unwrap());

    let inode = resolve_path(&proc_inner, AT_FDCWD, path).await?;
    if inode.metadata().mode == InodeMode::DIR {
        return Err(Errno::EISDIR);
    }

    drop(proc_inner);
    let file = inode.open()?;
    let elf_data = file.read_all().await?;
    let argc = current_process().execve(&elf_data, &args_vec, &envs_vec).await?;
    Ok(argc)
}

pub async fn sys_wait4(pid: Pid, wstatus: usize, options: u32, _rusage: usize) -> SyscallResult<usize> {
    info!("[sys_wait4] pid: {:?}, wstatus: {:?}, options: {:?}", pid as isize, wstatus, options);
    let options = WaitOptions::from_bits(options).ok_or(Errno::EINVAL)?;
    let ret = match select(
        WaitPidFuture::new(pid, options, wstatus),
        pin!(current_thread().event_bus.wait(Event::all().difference(Event::CHILD_EXIT))),
    ).await {
        Either::Left((pid, _)) => pid,
        Either::Right(_) => Err(Errno::EINTR),
    };
    info!("[sys_wait4] ret: {:?}", ret);
    ret
}
