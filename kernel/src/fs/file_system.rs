use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::fmt::Display;
use core::sync::atomic::{AtomicUsize, Ordering};
use hashbrown::HashMap;
use log::debug;
use crate::config::MAX_INODE_CACHE;
use crate::fs::ffi::{InodeMode, VfsFlags};
use crate::fs::inode::Inode;
use crate::fs::inode_cache::InodeCache;
use crate::fs::path::is_absolute_path;
use crate::result::{Errno, SyscallResult};
use crate::split_path;
use crate::sync::mutex::Mutex;

#[derive(Copy, Clone)]
#[repr(u64)]
pub enum FileSystemType {
    DEVFS = 0x62646576,
    EXT4 = 0xef53,
    FAT32 = 0x4d44,
    TMPFS = 0x01021994,
    PROCFS = 0x9fa0,
}

impl Display for FileSystemType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FileSystemType::DEVFS => write!(f, "devfs"),
            FileSystemType::EXT4 => write!(f, "ext4"),
            FileSystemType::FAT32 => write!(f, "fat32"),
            FileSystemType::TMPFS => write!(f, "tmpfs"),
            FileSystemType::PROCFS => write!(f, "proc"),
        }
    }
}

/// 文件系统元数据
///
/// 一个文件系统在刚创建时不关联任何挂载点，通过 `move_mount` 挂载到命名空间。
pub struct FileSystemMeta {
    /// 唯一标识符
    fsid: usize,

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
        let fsid = FS_ID_POOL.fetch_add(1, Ordering::Acquire);
        Self { fsid, fstype, flags }
    }
}

static FS_ID_POOL: AtomicUsize = AtomicUsize::new(1);
static MNT_ID_POOL: AtomicUsize = AtomicUsize::new(1);
static MNT_NS_ID_POOL: AtomicUsize = AtomicUsize::new(1);

/// 挂载命名空间
pub struct MountNamespace {
    pub mnt_ns_id: usize,
    pub inode_cache: InodeCache,
    inner: Mutex<NSInner>,
}

struct NSInner {
    tree: MountTree,
    snapshot: HashMap<usize, (usize, String)>,
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
        Self { mnt_id, fs, sub_trees: BTreeMap::new() }
    }
}

impl MountNamespace {
    pub fn new(root_fs: Arc<dyn FileSystem>) -> Self {
        let tree = MountTree::new(root_fs);
        let snapshot = (tree.fs.metadata().fsid, (tree.mnt_id, "/".to_string()));
        Self {
            mnt_ns_id: MNT_NS_ID_POOL.fetch_add(1, Ordering::Acquire),
            inode_cache: InodeCache::new(MAX_INODE_CACHE),
            inner: Mutex::new(NSInner { tree, snapshot: HashMap::from([snapshot]) }),
        }
    }

    pub fn print_mounts(&self) -> String {
        let mut res = String::new();
        res += "/dev/sda1 / ext4 rw 0 0\n";
        res += "dev /dev devtmpfs rw 0 0\n";
        res += "proc /proc proc rw 0 0\n";
        res
    }

    pub async fn lookup_absolute(
        &self,
        path: &str,
        follow_link: bool,
    ) -> SyscallResult<Arc<dyn Inode>> {
        assert!(is_absolute_path(path));
        let root = self.inner.lock().tree.fs.root();
        let inode = self.lookup_relative(root, &path[1..], follow_link).await?;
        // self.inode_cache.insert(None, path.to_string(), &inode);
        Ok(inode)
    }

    pub async fn lookup_relative(
        &self,
        parent: Arc<dyn Inode>,
        path: &str,
        follow_link: bool,
    ) -> SyscallResult<Arc<dyn Inode>> {
        assert!(!is_absolute_path(&path));
        let mut names = split_path!(path).map(|s| s.to_string()).collect::<VecDeque<_>>();
        let mut inode = parent.clone();
        loop {
            if inode.metadata().mode == InodeMode::IFLNK && (!names.is_empty() || follow_link) {
                let path = inode.clone().do_readlink().await?;
                debug!("[lookup] Follow link: {}", path);
                inode = if is_absolute_path(&path) {
                    self.inner.lock().tree.fs.root()
                } else {
                    match inode.metadata().parent.clone().unwrap().upgrade() {
                        Some(parent) => parent,
                        None => return Err(Errno::EIO),
                    }
                };
                names = split_path!(path).map(|s| s.to_string()).chain(names).collect();
            }
            if let Some(name) = names.pop_front() {
                if name == ".." {
                    if let Some(parent) = inode.metadata().parent.clone() {
                        inode = match parent.upgrade() {
                            Some(parent) => parent,
                            None => return Err(Errno::EIO),
                        }
                    }
                } else {
                    inode = inode.lookup_name(&name).await?;
                }
            } else {
                // self.inode_cache.insert(Some(&parent), path.to_string(), &inode);
                break Ok(inode);
            }
        }
    }

    pub async fn mount<F>(&self, absolute_path: &str, fs_fn: F) -> SyscallResult
    where
        F: FnOnce(Arc<dyn Inode>) -> Arc<dyn FileSystem>,
    {
        assert!(is_absolute_path(absolute_path));
        let inode = self.lookup_absolute(absolute_path, false).await?;
        let inode = inode.metadata().parent.clone().unwrap().upgrade().unwrap();
        let dir_name = absolute_path.rsplit_once('/').unwrap().1.to_string();
        let fs = fs_fn(inode.clone());
        let mut inner = self.inner.lock();
        let mnt_id = Self::do_mount(&mut inner.tree.sub_trees, fs.clone(), absolute_path)?;
        inner.snapshot.insert(fs.metadata().fsid, (mnt_id, absolute_path.to_string()));
        inode.metadata().inner.lock().mounts.insert(dir_name, fs.root());
        // self.inode_cache.invalidate();
        Ok(())
    }

    pub async fn unmount(&self, absolute_path: &str) -> SyscallResult {
        assert!(is_absolute_path(absolute_path));
        let inode = self.lookup_absolute(absolute_path, false).await?;
        let inode = inode.metadata().parent.clone().unwrap().upgrade().unwrap();
        let dir_name = absolute_path.rsplit_once('/').unwrap().1.to_string();
        let mut inner = self.inner.lock();
        let tree = Self::do_unmount(&mut inner.tree.sub_trees, absolute_path)?;
        inner.snapshot.remove(&tree.fs.metadata().fsid);
        inode.metadata().inner.lock().mounts.remove(&dir_name);
        // self.inode_cache.invalidate();
        Ok(())
    }

    pub fn get_inode_snapshot(&self, inode: &dyn Inode) -> SyscallResult<(usize, String)> {
        let fsid = inode.file_system().upgrade().ok_or(Errno::EIO)?.metadata().fsid;
        Ok(self.inner.lock().snapshot.get(&fsid).cloned().expect("fsid not found"))
    }

    fn do_mount(
        sub_trees: &mut BTreeMap<String, MountTree>,
        fs: Arc<dyn FileSystem>,
        path: &str,
    ) -> SyscallResult<usize> {
        for (k, v) in sub_trees.iter_mut() {
            if k == path {
                return Err(Errno::EEXIST);
            } else if path.starts_with(k) && path.trim_start_matches(k).starts_with('/') {
                return Self::do_mount(&mut v.sub_trees, fs, &path[k.len()..]);
            }
        }
        let tree = MountTree::new(fs);
        let mnt_id = tree.mnt_id;
        sub_trees.insert(path.to_string(), tree);
        Ok(mnt_id)
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
