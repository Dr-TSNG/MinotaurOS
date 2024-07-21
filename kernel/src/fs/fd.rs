use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use smoltcp::wire::IpListenEndpoint;
use crate::config::MAX_FD_NUM;
use crate::fs::devfs::tty::DEFAULT_TTY;
use crate::fs::file::File;
use crate::result::{Errno, SyscallResult};
use crate::process::ffi::{Rlimit};
use crate::processor::current_process;

pub type FdNum = i32;

#[derive(Clone)]
pub struct FdTable {
    table: Vec<Option<FileDescriptor>>,
    pub rlimit: Rlimit,
}

#[derive(Clone)]
pub struct FileDescriptor {
    pub file: Arc<dyn File>,
    pub cloexec: bool,
}

impl FileDescriptor {
    pub fn new(file: Arc<dyn File>, cloexec: bool) -> Self {
        Self { file, cloexec }
    }
}

impl FdTable {
    pub fn new() -> Self {
        let mut table = vec![];
        let stdin = FileDescriptor::new(DEFAULT_TTY.clone(), false);
        let stdout = FileDescriptor::new(DEFAULT_TTY.clone(), false);
        let stderr = FileDescriptor::new(DEFAULT_TTY.clone(), false);
        table.push(Some(stdin));
        table.push(Some(stdout));
        table.push(Some(stderr));
        FdTable {
            table,
            rlimit: Rlimit {
                rlim_cur: MAX_FD_NUM,
                rlim_max: MAX_FD_NUM,
            },
        }
    }

    pub fn cloexec(&mut self) {
        for fd in self.table.iter_mut() {
            fd.take_if(|fd| fd.cloexec);
        }
    }

    /// 获取指定位置的文件描述符
    pub fn get(&self, fd: FdNum) -> SyscallResult<FileDescriptor> {
        self.table.get(fd as usize).and_then(Option::clone).ok_or(Errno::EBADF)
    }

    /// 获取指定位置的文件描述符的可变引用
    pub fn get_mut(&mut self, fd: FdNum) -> SyscallResult<&mut FileDescriptor> {
        self.table.get_mut(fd as usize).and_then(Option::as_mut).ok_or(Errno::EBADF)
    }

    /// 插入一个文件描述符，返回位置
    pub fn put(&mut self, fd_impl: FileDescriptor, start: FdNum) -> SyscallResult<FdNum> {
        let fd = self.find_slot(start as usize);
        let proc_inner = current_process().inner.lock();
        if fd > proc_inner.fd_table.rlimit.rlim_max - 1 {
            return Err(Errno::EMFILE);
        }
        if fd >= self.table.len() {
            self.table.resize(fd + 1, None);
        }
        self.table[fd] = Some(fd_impl);
        Ok(fd as i32)
    }

    /// 在指定位置插入一个文件描述符，如果位置已经占用，则替换
    pub fn insert(&mut self, fd: FdNum, fd_impl: FileDescriptor) -> SyscallResult {
        let fd = fd as usize;
        if fd > MAX_FD_NUM {
            return Err(Errno::EBADF);
        }
        if fd >= self.table.len() {
            self.table.resize(fd + 1, None);
        }
        self.table[fd] = Some(fd_impl);
        Ok(())
    }

    /// 删除一个文件描述符
    pub fn remove(&mut self, fd: FdNum) -> SyscallResult<()> {
        self.table.get_mut(fd as usize).and_then(Option::take).ok_or(Errno::EBADF)?;
        Ok(())
    }

    pub fn socket_can_bind(&self, endpoint: IpListenEndpoint) -> bool {
        for fd_impl in self.table.iter() {
            if let Some(fd_impl) = fd_impl {
                if let Ok(socket) = fd_impl.file.clone().as_socket() {
                    if socket.local_endpoint() == endpoint {
                        return false;
                    }
                }
            }
        }
        true
    }
}

impl FdTable {
    fn find_slot(&self, start: usize) -> usize {
        if start >= self.table.len() {
            return start;
        }
        for i in start..self.table.len() {
            if self.table[i].is_none() {
                return i;
            }
        }
        self.table.len()
    }
}
