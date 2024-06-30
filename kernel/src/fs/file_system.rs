use crate::fs::ffi::VfsFlags;
use crate::fs::inode::Inode;
use crate::fs::path::is_absolute_path;
use crate::result::{Errno, SyscallResult};
use crate::sync::mutex::Mutex;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

#[derive(Copy, Clone)]
#[repr(u64)]
pub enum FileSystemType {
    DEVFS = 0x62646576,
    FAT32 = 0x4d44,
    TMPFS = 0x01021994,
    PROCFS = 0x9fa0,
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
pub trait FileSystem: Send + Sync {
    /// 文件系统元数据
    fn metadata(&self) -> &FileSystemMeta;

    /// 根 Inode
    fn root(&self) -> Arc<dyn Inode>;
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
    tree: Mutex<MountTree>,
}

/// 挂载树
struct MountTree {
    mnt_id: usize,
    fs: Arc<dyn FileSystem>,
    /// 子挂载树，`key` 为挂载路径，以 `/` 开头
    sub_trees: BTreeMap<String, MountTree>,
}

impl MountTree {
    pub fn new(fs: Arc<dyn FileSystem>) -> Self {
        let mnt_id = MNT_ID_POOL.fetch_add(1, Ordering::Acquire);
        Self {
            mnt_id,
            fs,
            sub_trees: BTreeMap::new(),
        }
    }
}

impl MountNamespace {
    pub fn new(root_fs: Arc<dyn FileSystem>) -> Self {
        let mnt_ns_id = MNT_NS_ID_POOL.fetch_add(1, Ordering::Acquire);
        let tree = Mutex::new(MountTree::new(root_fs));
        Self { mnt_ns_id, tree }
    }

    pub async fn lookup_absolute(&self, path: &str) -> SyscallResult<Arc<dyn Inode>> {
        assert!(is_absolute_path(path));
        let root = self.tree.lock().fs.root();
        root.lookup_relative(&path[1..]).await
    }

    pub async fn mount<F>(&self, absolute_path: &str, fs_fn: F) -> SyscallResult
    where
        F: FnOnce(Arc<dyn Inode>) -> Arc<dyn FileSystem>,
    {
        assert!(is_absolute_path(absolute_path));
        let inode = self.lookup_absolute(absolute_path).await?;
        let inode = inode.metadata().parent.clone().unwrap().upgrade().unwrap();
        let dir_name = absolute_path.rsplit_once('/').unwrap().1.to_string();
        let fs = fs_fn(inode.clone());
        let mut tree = self.tree.lock();
        Self::do_mount(&mut tree.sub_trees, fs.clone(), absolute_path)?;
        inode
            .metadata()
            .inner
            .lock()
            .mounts
            .insert(dir_name, fs.root());
        Ok(())
    }

    pub async fn unmount(&self, absolute_path: &str) -> SyscallResult {
        assert!(is_absolute_path(absolute_path));
        let inode = self.lookup_absolute(absolute_path).await?;
        let inode = inode.metadata().parent.clone().unwrap().upgrade().unwrap();
        let dir_name = absolute_path.rsplit_once('/').unwrap().1.to_string();
        let mut tree = self.tree.lock();
        Self::do_unmount(&mut tree.sub_trees, absolute_path)?;
        inode.metadata().inner.lock().mounts.remove(&dir_name);
        Ok(())
    }

    fn do_mount(
        sub_trees: &mut BTreeMap<String, MountTree>,
        fs: Arc<dyn FileSystem>,
        path: &str,
    ) -> SyscallResult {
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

    fn do_unmount(
        sub_trees: &mut BTreeMap<String, MountTree>,
        path: &str,
    ) -> SyscallResult<MountTree> {
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
