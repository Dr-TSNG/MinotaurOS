use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use crate::config::MAX_FD_NUM;
use crate::driver::tty::DEFAULT_TTY;
use crate::fs::ffi::OpenFlags;
use crate::fs::file::File;
use crate::result::{Errno, SyscallResult};

pub type FdNum = i32;

#[derive(Clone)]
pub struct FdTable {
    table: Vec<Option<FileDescriptor>>,
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
        FdTable { table }
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

    /// 插入一个文件描述符，返回位置
    pub fn put(&mut self, fd_impl: FileDescriptor) -> SyscallResult<FdNum> {
        let fd = self.find_slot();
        if fd > MAX_FD_NUM {
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
}

impl FdTable {
    fn find_slot(&self) -> usize {
        for (i, fd) in self.table.iter().enumerate() {
            if fd.is_none() {
                return i;
            }
        }
        self.table.len()
    }
}
