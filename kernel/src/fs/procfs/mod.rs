use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicUsize, Ordering};
use async_trait::async_trait;
use tap::Tap;
use crate::fs::ffi::{InodeMode, VfsFlags};
use crate::fs::file_system::{FileSystem, FileSystemMeta, FileSystemType};
use crate::fs::inode::{Inode, InodeInternal, InodeMeta};
use crate::fs::procfs::meminfo::MeminfoInode;
use crate::fs::procfs::mounts::MountsInode;
use crate::fs::procfs::process::ProcessDirInode;
use crate::process::monitor::MONITORS;
use crate::process::{Pid, Process};
use crate::result::{Errno, SyscallResult};
use crate::sched::ffi::TimeSpec;
use crate::sync::mutex::Mutex;
use crate::sync::once::LateInit;

mod mounts;
mod meminfo;
mod process;

pub struct ProcFileSystem {
    vfsmeta: FileSystemMeta,
    flags: VfsFlags,
    ino_pool: AtomicUsize,
    root: LateInit<Arc<RootInode>>,
}

impl ProcFileSystem {
    pub fn new(mut flags: VfsFlags, parent: Option<Arc<dyn Inode>>) -> Arc<Self> {
        flags |= VfsFlags::ST_WRITE | VfsFlags::ST_RELATIME;
        let fs = Arc::new(Self {
            vfsmeta: FileSystemMeta::new(0, "proc", FileSystemType::PROCFS),
            flags,
            ino_pool: AtomicUsize::new(1),
            root: LateInit::new(),
        });
        fs.root.init(RootInode::new(&fs, parent));
        fs
    }

    pub fn add_process(self: Arc<Self>, process: Arc<Process>) {
        let root = self.root.clone();
        root.children.lock().insert(
            process.pid.0.to_string(),
            ProcessDirInode::new(self, root.clone(), process),
        );
    }

    pub fn remove_process(self: Arc<Self>, pid: Pid) {
        self.root.children.lock().remove(&pid.to_string());
    }
}

impl FileSystem for ProcFileSystem {
    fn metadata(&self) -> &FileSystemMeta {
        &self.vfsmeta
    }

    fn flags(&self) -> VfsFlags {
        self.flags
    }

    fn root(&self) -> Arc<dyn Inode> {
        self.root.clone()
    }
}

struct RootInode {
    metadata: InodeMeta,
    fs: Weak<ProcFileSystem>,
    children: Mutex<BTreeMap<String, Arc<dyn Inode>>>,
}

impl RootInode {
    pub fn new(fs: &Arc<ProcFileSystem>, parent: Option<Arc<dyn Inode>>) -> Arc<Self> {
        let root = Arc::new(Self {
            metadata: InodeMeta::new(
                fs.ino_pool.fetch_add(1, Ordering::Relaxed),
                0,
                0,
                0,
                InodeMode::S_IFDIR | InodeMode::from_bits_truncate(0o555),
                String::new(),
                String::new(),
                parent,
                None,
                TimeSpec::default(),
                TimeSpec::default(),
                TimeSpec::default(),
                0,
            ),
            fs: Arc::downgrade(fs),
            children: Mutex::new(BTreeMap::new()),
        });
        root.children.lock().tap_mut(|it| {
            it.insert("mounts".to_string(), MountsInode::new(fs.clone(), root.clone()));
            it.insert("meminfo".to_string(), MeminfoInode::new(fs.clone(), root.clone()));
            for process in MONITORS.lock().process.all() {
                it.insert(
                    process.pid.0.to_string(),
                    ProcessDirInode::new(fs.clone(), root.clone(), process),
                );
            }
        });
        root
    }
}

#[async_trait]
impl InodeInternal for RootInode {
    async fn do_lookup_name(self: Arc<Self>, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        self.children.lock().get(name).cloned().ok_or(Errno::ENOENT)
    }

    async fn do_lookup_idx(self: Arc<Self>, idx: usize) -> SyscallResult<Arc<dyn Inode>> {
        self.children.lock().values().nth(idx).cloned().ok_or(Errno::ENOENT)
    }
}

impl Inode for RootInode {
    fn metadata(&self) -> &InodeMeta {
        &self.metadata
    }

    fn file_system(&self) -> Weak<dyn FileSystem> {
        self.fs.clone()
    }
}
