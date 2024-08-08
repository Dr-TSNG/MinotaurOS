mod kernel;

use alloc::sync::Arc;
use alloc::vec;
use crate::fs::inode::Inode;
use crate::fs::procfs::ndir::SimpleDirInode;
use crate::fs::procfs::ProcFileSystem;
use crate::fs::procfs::sys::kernel::new_kernel_dir;

pub fn new_sys_dir(fs: Arc<ProcFileSystem>, parent: Arc<dyn Inode>) -> Arc<dyn Inode> {
    SimpleDirInode::new(fs.clone(), parent, 0o555, "sys", |dir| {
        vec![
            new_kernel_dir(fs, dir),
        ]
    })
}
