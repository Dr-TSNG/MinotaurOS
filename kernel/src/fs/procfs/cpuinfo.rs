use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use core::cmp::min;
use core::sync::atomic::Ordering;
use async_trait::async_trait;
use macros::InodeFactory;
use crate::driver::BOARD_INFO;
use crate::fs::ffi::InodeMode;
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::fs::procfs::ProcFileSystem;
use crate::result::SyscallResult;

#[derive(InodeFactory)]
pub struct CpuInfoInode {
    metadata: InodeMeta,
    fs: Weak<ProcFileSystem>,
}

impl CpuInfoInode {
    pub fn new(fs: Arc<ProcFileSystem>, parent: Arc<dyn Inode>) -> Arc<Self> {
        Arc::new(Self {
            metadata: InodeMeta::new_simple(
                fs.ino_pool.fetch_add(1, Ordering::Relaxed),
                0,
                0,
                InodeMode::S_IFREG | InodeMode::from_bits_retain(0o444),
                "cpuinfo".to_string(),
                parent,
            ),
            fs: Arc::downgrade(&fs),
        })
    }
}

#[async_trait]
impl InodeInternal for CpuInfoInode {
    async fn read_direct(&self, buf: &mut [u8], offset: isize) -> SyscallResult<isize> {
        let cpuinfo = print_cpuinfo();
        if offset as usize >= cpuinfo.len() {
            return Ok(0);
        }
        let copy = min(buf.len(), cpuinfo.len() - offset as usize);
        let to_copy = &cpuinfo.as_bytes()[offset as usize..offset as usize + copy];
        buf[..copy].copy_from_slice(to_copy);
        Ok(copy as isize)
    }
}

fn print_cpuinfo() -> String {
    let mut cpuinfo = String::new();
    for hart in 0..BOARD_INFO.smp {
        cpuinfo.push_str(&format!("{:<16}: {}\n", "processor", hart));
        cpuinfo.push_str(&format!("{:<16}: {}\n", "hart", hart));
        cpuinfo.push_str(&format!("{:<16}: {}\n", "isa", "rv64imafdc"));
        cpuinfo.push_str(&format!("{:<16}: {}\n", "mmu", "sv39"));
        cpuinfo.push_str(&format!("{:<16}: {}\n", "uarch", "qemu"));
        cpuinfo.push('\n');
    }
    cpuinfo
}
