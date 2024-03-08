use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::ops::Deref;
use core::sync::atomic::{AtomicUsize, Ordering};
use async_trait::async_trait;
use crate::fs::ffi::VfsFlags;
use crate::fs::inode::Inode;
use crate::result::{Errno, MosResult, SyscallResult};
use crate::sync::mutex::Mutex;

pub enum FileSystemType {
    FAT32,
    TMPFS,
    PROCFS,
}

/// 文件系统元数据
///
/// 一个文件系统在刚创建时不关联任何挂载点，通过 `move_mount` 挂载到命名空间。
pub struct FileSystemMeta {
    /// 文件系统类型
    pub fstype: FileSystemType,

    /// 文件系统标志
    pub flags: VfsFlags,
}

/// 文件系统
#[async_trait]
pub trait FileSystem: Send + Sync {
    /// 文件系统元数据
    fn metadata(&self) -> &FileSystemMeta;

    /// 根 Inode
    async fn root(self: Arc<Self>) -> MosResult<Arc<dyn Inode>>;
}

impl FileSystemMeta {
    pub fn new(fstype: FileSystemType, flags: VfsFlags) -> Self {
        Self { fstype, flags }
    }
}

static MNT_ID_POOL: AtomicUsize = AtomicUsize::new(1);
static MNT_NS_ID_POOL: AtomicUsize = AtomicUsize::new(1);

/// 挂载命名空间
pub struct MountNamespace {
    pub mnt_ns_id: usize,
    pub tree: Mutex<MountTree>,
}

/// 挂载树
pub struct MountTree {
    pub mnt_id: usize,
    pub fs: Arc<dyn FileSystem>,
    /// 子挂载树，`key` 为挂载路径，以 `/` 开头
    pub sub_trees: BTreeMap<String, MountTree>,
}

impl MountTree {
    pub fn new(fs: Arc<dyn FileSystem>) -> Self {
        let mnt_id = MNT_ID_POOL.fetch_add(1, Ordering::Acquire);
        Self { mnt_id, fs, sub_trees: BTreeMap::new() }
    }
}

impl MountNamespace {
    pub fn new(root_fs: Arc<dyn FileSystem>) -> Self {
        let mnt_ns_id = MNT_NS_ID_POOL.fetch_add(1, Ordering::Acquire);
        let tree = Mutex::new(MountTree::new(root_fs));
        Self { mnt_ns_id, tree }
    }
    
    pub fn resolve<'a>(&self, absolute_path: &'a str) -> SyscallResult<(Arc<dyn FileSystem>, &'a str)> {
        let tree = self.tree.lock();
        let mut tree = tree.deref();
        let mut path = absolute_path;
        'l: loop {
            for (k, v) in tree.sub_trees.iter() {
                // Example: path = "/mnt", k = "/mnt"
                if path == k {
                    return Ok((v.fs.clone(), "/"));
                }
                // Example: path = "/proc/1/cmdline", k = "/proc"
                if path.starts_with(k) && path.trim_start_matches(k).starts_with('/') {
                    // Example: path = "/1/cmdline"
                    path = &path[k.len()..];
                    tree = v;
                    continue 'l;
                }
            }
            // Example: path = "/", no matched subtree
            return Ok((tree.fs.clone(), path));
        }
    }

    pub fn mount(&self, fs: Arc<dyn FileSystem>, path: &str) -> SyscallResult {
        let mut tree = self.tree.lock();
        Self::do_mount(&mut tree.sub_trees, fs, path)?;
        Ok(())
    }

    pub fn unmount(&self, path: &str) -> SyscallResult {
        let mut tree = self.tree.lock();
        Self::do_unmount(&mut tree.sub_trees, path)?;
        Ok(())
    }

    fn do_mount(sub_trees: &mut BTreeMap<String, MountTree>, fs: Arc<dyn FileSystem>, path: &str) -> SyscallResult {
        for (k, v) in sub_trees.iter_mut() {
            if k == path {
                return Err(Errno::EEXIST);
            } else if path.starts_with(k) && path.trim_start_matches(k).starts_with('/') {
                return Self::do_mount(&mut v.sub_trees, fs, &path[k.len()..]);
            }
        }
        sub_trees.insert(path.to_string(), MountTree::new(fs));
        Ok(())
    }

    fn do_unmount(sub_trees: &mut BTreeMap<String, MountTree>, path: &str) -> SyscallResult<MountTree> {
        for (k, v) in sub_trees.iter_mut() {
            if k == path {
                return if v.sub_trees.is_empty() {
                    Ok(sub_trees.remove(path).unwrap())
                } else {
                    Err(Errno::EBUSY)
                };
            } else if path.starts_with(k) && path.trim_start_matches(k).starts_with('/') {
                return Self::do_unmount(&mut v.sub_trees, &path[k.len()..]);
            }
        }
        Err(Errno::EINVAL)
    }
}
