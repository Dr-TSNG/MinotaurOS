mod pid_max;

use alloc::sync::Arc;
use alloc::vec;
use crate::fs::inode::Inode;
use crate::fs::procfs::ndir::SimpleDirInode;
use crate::fs::procfs::ProcFileSystem;
use crate::fs::procfs::sys::kernel::pid_max::PidMaxInode;

pub fn new_kernel_dir(fs: Arc<ProcFileSystem>, parent: Arc<dyn Inode>) -> Arc<dyn Inode> {
    SimpleDirInode::new(fs.clone(), parent, 0o555, "kernel", |dir| {
        vec![
            PidMaxInode::new(fs, dir),
        ]
    })
}
