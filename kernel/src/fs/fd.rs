use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use crate::fs::devfs::tty::TTY;
use crate::fs::ffi::OpenFlags;
use crate::fs::file::File;

pub type Fd = usize;

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
}

impl FdTable {
    pub fn new() -> Self {
        let mut table = vec![];
        let stdin = FileDescriptor::new(TTY.clone(), OpenFlags::O_RDONLY);
        let stdout = FileDescriptor::new(TTY.clone(), OpenFlags::O_WRONLY);
        let stderr = FileDescriptor::new(TTY.clone(), OpenFlags::O_WRONLY);
        table.push(Some(stdin));
        table.push(Some(stdout));
        table.push(Some(stderr));
        FdTable { table }
    }
}
