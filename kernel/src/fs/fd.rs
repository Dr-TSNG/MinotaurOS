use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use crate::config::MAX_FD_NUM;
use crate::fs::devfs::tty::DEFAULT_TTY;
use crate::fs::ffi::OpenFlags;
use crate::fs::file::File;
use crate::result::{Errno, SyscallResult};
use crate::process::ffi::{Rlimit};
use crate::processor::current_process;

pub type FdNum = i32;

#[derive(Clone)]
pub struct FdTable {
    table: Vec<Option<FileDescriptor>>,
    pub rlimit: Rlimit
}

#[derive(Clone)]
pub struct FileDescriptor {
    pub file: Arc<dyn File>,
    pub flags: OpenFlags,
}

impl FileDescriptor {
    pub fn new(file: Arc<dyn File>, flags: OpenFlags) -> Self {
        Self { file, flags }
    }

    pub fn dup(mut self, cloexec: bool) -> Self {
        if cloexec {
            self.flags.insert(OpenFlags::O_CLOEXEC);
        } else {
            self.flags.remove(OpenFlags::O_CLOEXEC);
        }
        self
    }
}

impl FdTable {
    pub fn new() -> Self {
        let mut table = vec![];
        let stdin = FileDescriptor::new(DEFAULT_TTY.clone(), OpenFlags::O_RDONLY);
        let stdout = FileDescriptor::new(DEFAULT_TTY.clone(), OpenFlags::O_WRONLY);
        let stderr = FileDescriptor::new(DEFAULT_TTY.clone(), OpenFlags::O_WRONLY);
        table.push(Some(stdin));
        table.push(Some(stdout));
        table.push(Some(stderr));
        FdTable {
            table,
            rlimit: Rlimit {
                rlim_cur: MAX_FD_NUM,
                rlim_max: MAX_FD_NUM},
        }
    }

    pub fn cloexec(&mut self) {
        for fd in self.table.iter_mut() {
            if let Some(fd_impl) = fd {
                if fd_impl.flags.contains(OpenFlags::O_CLOEXEC) {
                    *fd = None;
                }
            }
        }
    }

    /// 获取指定位置的文件描述符
    pub fn get(&self, fd: FdNum) -> SyscallResult<FileDescriptor> {
        let fd = fd as usize;
        self.table.get(fd).and_then(Option::clone).ok_or(Errno::EBADF)
    }

    /// 获取引用
    pub fn get_ref(&self, fd: FdNum) -> Option<&FileDescriptor> {
        if fd > self.table.len() as i32 {
            None
        } else {
            self.table[fd as usize].as_ref()
        }
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
    pub fn remove(&mut self, fd: FdNum) -> SyscallResult {
        let fd = fd as usize;
        if fd >= self.table.len() {
            return Err(Errno::EBADF);
        }
        self.table[fd] = None;
        Ok(())
    }

    /// 获取一个文件描述符的所有权
    pub fn take(&mut self, fd: FdNum) -> SyscallResult<Option<FileDescriptor>> {
        if fd >= self.table.len() as i32 {
            Ok(None)
        } else {
            Ok(self.table[fd as usize].take())
        }
    }

    pub fn alloc_fd(&mut self) -> SyscallResult<usize> {
        if let Some(fd) = self.free_slot() {
            Ok(fd)
        } else {
            self.table.push(None);
            Ok(self.table.len() - 1)
        }
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

    fn free_slot(&self) -> Option<usize> {
        (0..self.table.len()).find(|fd| self.table[*fd].is_none())
    }

    pub fn set_rlimit(&mut self, rlimit: Rlimit) {
        self.rlimit = rlimit;
    }
}

