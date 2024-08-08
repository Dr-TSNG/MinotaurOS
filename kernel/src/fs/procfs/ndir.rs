use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use async_trait::async_trait;
use macros::InodeFactory;
use crate::fs::ffi::InodeMode;
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::fs::procfs::ProcFileSystem;
use crate::result::{Errno, SyscallResult};
use crate::sync::once::LateInit;

#[derive(InodeFactory)]
pub struct SimpleDirInode {
    metadata: InodeMeta,
    fs: Weak<ProcFileSystem>,
    children: LateInit<BTreeMap<String, Arc<dyn Inode>>>,
}

impl SimpleDirInode {
    pub fn new(
        fs: Arc<ProcFileSystem>,
        parent: Arc<dyn Inode>,
        acc_mode: u32,
        name: &str,
        children: impl FnOnce(Arc<dyn Inode>) -> Vec<Arc<dyn Inode>>,
    ) -> Arc<Self> {
        let this = Arc::new(Self {
            metadata: InodeMeta::new_simple(
                fs.ino_pool.fetch_add(1, Ordering::Relaxed),
                0,
                0,
                InodeMode::S_IFDIR | InodeMode::from_bits_retain(acc_mode),
                name.to_string(),
                parent,
            ),
            fs: Arc::downgrade(&fs),
            children: LateInit::new(),
        });
        let children = children(this.clone())
            .into_iter()
            .map(|inode| {
                let name = inode.metadata().name.clone();
                (name, inode)
            })
            .collect();
        this.children.init(children);
        this
    }
}

#[async_trait]
impl InodeInternal for SimpleDirInode {
    async fn do_lookup_name(self: Arc<Self>, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        self.children.get(name).cloned().ok_or(Errno::ENOENT)
    }

    async fn do_lookup_idx(self: Arc<Self>, idx: usize) -> SyscallResult<Arc<dyn Inode>> {
        self.children.values().nth(idx).cloned().ok_or(Errno::ENOENT)
    }
}
