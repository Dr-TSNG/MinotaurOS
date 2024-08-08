use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use core::sync::atomic::Ordering;
use async_trait::async_trait;
use macros::InodeFactory;
use crate::fs::ffi::InodeMode;
use crate::fs::procfs::ProcFileSystem;
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::result::SyscallResult;

#[derive(InodeFactory)]
pub struct MeminfoInode {
    metadata: InodeMeta,
    fs: Weak<ProcFileSystem>,
}

impl MeminfoInode {
    pub fn new(fs: Arc<ProcFileSystem>, parent: Arc<dyn Inode>) -> Arc<Self> {
        Arc::new(Self {
            metadata: InodeMeta::new_simple(
                fs.ino_pool.fetch_add(1, Ordering::Relaxed),
                0,
                0,
                InodeMode::S_IFREG | InodeMode::from_bits_retain(0o444),
                "meminfo".to_string(),
                parent,
            ),
            fs: Arc::downgrade(&fs),
        })
    }
}

#[async_trait]
impl InodeInternal for MeminfoInode {
    async fn read_direct(&self, buf: &mut [u8], offset: isize) -> SyscallResult<isize> {
        let meminfo = Meminfo::new();
        let buf_str = meminfo.default();
        let len = buf_str.len();
        if offset == len as isize {
            Ok(0)
        } else {
            buf[..len].copy_from_slice(buf_str.as_bytes());
            Ok(len as isize)
        }
    }

    async fn write_direct(&self, _: &[u8], _: isize) -> SyscallResult<isize> {
        Ok(0)
    }
}

const TOTAL_MEM: usize = 16251136;
const FREE_MEM: usize = 327680;
const BUFFER: usize = 373336;
const CACHED: usize = 10391984;
const TOTAL_SWAP: usize = 4194300;
pub struct Meminfo {
    /// General memory
    pub total_mem: usize,
    pub free_mem: usize,
    pub avail_mem: usize,
    /// Buffer and cache
    pub buffers: usize,
    pub cached: usize,
    /// Swap space
    pub total_swap: usize,
    pub free_swap: usize,
    /// Share memory
    pub shmem: usize,
    pub slab: usize,
}

impl Meminfo {
    pub const fn new() -> Self {
        Self {
            total_mem: TOTAL_MEM,
            free_mem: FREE_MEM,
            avail_mem: TOTAL_MEM - FREE_MEM,
            buffers: BUFFER,
            cached: CACHED,
            total_swap: TOTAL_SWAP,
            free_swap: TOTAL_SWAP,
            shmem: 0,
            slab: 0,
        }
    }

    pub fn default(&self) -> String {
        let mut res = "".to_string();
        let end = " KB\n";
        let total_mem = "MemTotal:\t".to_string() + self.total_mem.to_string().as_str() + end;
        let free_mem = "MemFree:\t".to_string() + self.free_mem.to_string().as_str() + end;
        let avail_mem = "MemAvailable:\t".to_string() + self.avail_mem.to_string().as_str() + end;
        let buffers = "Buffers:\t".to_string() + self.buffers.to_string().as_str() + end;
        let cached = "Cached:\t".to_string() + self.cached.to_string().as_str() + end;
        let cached_swap = "SwapCached:\t".to_string() + 0.to_string().as_str() + end;
        let total_swap = "SwapTotal:\t".to_string() + self.total_swap.to_string().as_str() + end;
        let free_swap = "SwapFree:\t".to_string() + self.free_swap.to_string().as_str() + end;
        let shmem = "Shmem:\t".to_string() + self.shmem.to_string().as_str() + end;
        let slab = "Slab:\t".to_string() + self.slab.to_string().as_str() + end;
        res += total_mem.as_str();
        res += free_mem.as_str();
        res += avail_mem.as_str();
        res += buffers.as_str();
        res += cached.as_str();
        res += cached_swap.as_str();
        res += total_swap.as_str();
        res += free_swap.as_str();
        res += shmem.as_str();
        res += slab.as_str();
        res
    }
}
