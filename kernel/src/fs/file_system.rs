use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use core::fmt::Display;
use core::sync::atomic::{AtomicUsize, Ordering};
use hashbrown::HashMap;
use log::debug;
use tap::Tap;
use crate::config::MAX_SYMLINKS;
use crate::driver::ffi::sep_dev;
use crate::fs::devfs::DevFileSystem;
use crate::fs::ffi::{InodeMode, VfsFlags};
use crate::fs::inode::Inode;
use crate::fs::path::is_absolute_path;
use crate::fs::procfs::ProcFileSystem;
use crate::fs::tmpfs::TmpFileSystem;
use crate::process::token::AccessToken;
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
            FileSystemType::DEVFS => write!(f, "devtmpfs"),
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

    /// 设备号
    pub dev: u64,

    /// 挂载源
    pub source: String,

    /// 文件系统类型
    pub fstype: FileSystemType,
}

/// 文件系统
#[allow(unused)]
pub trait FileSystem: Send + Sync {
    /// 文件系统元数据
    fn metadata(&self) -> &FileSystemMeta;

    /// 文件系统标志
    fn flags(&self) -> VfsFlags;

    /// 根 Inode
    fn root(&self) -> Arc<dyn Inode>;

    /// 重新挂载
    fn remount(&self, flags: VfsFlags) -> SyscallResult {
        Err(Errno::EOPNOTSUPP)
    }
}

impl FileSystemMeta {
    pub fn new(dev: u64, source: &str, fstype: FileSystemType) -> Self {
        let fsid = FS_ID_POOL.fetch_add(1, Ordering::Acquire);
        let source = source.to_string();
        Self { dev, source, fsid, fstype }
    }
}

static FS_ID_POOL: AtomicUsize = AtomicUsize::new(1);
static MNT_ID_POOL: AtomicUsize = AtomicUsize::new(1);
static MNT_NS_ID_POOL: AtomicUsize = AtomicUsize::new(1);

/// 挂载命名空间
pub struct MountNamespace {
    pub mnt_ns_id: usize,
    inner: Mutex<NSInner>,
}

struct NSInner {
    tree: MountTree,
    procfs: Weak<ProcFileSystem>,
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
        let snapshot = (tree.fs.metadata().fsid, (tree.mnt_id, String::new()));
        Self {
            mnt_ns_id: MNT_NS_ID_POOL.fetch_add(1, Ordering::Acquire),
            inner: Mutex::new(NSInner {
                tree,
                procfs: Weak::new(),
                snapshot: HashMap::from([snapshot]),
            }),
        }
    }

    pub fn proc_fs(&self) -> Weak<ProcFileSystem> {
        self.inner.lock().procfs.clone()
    }

    pub fn print_mounts(&self) -> String {
        let mut res = String::new();
        let inner = self.inner.lock();
        let mut queue = VecDeque::from([&inner.tree]);
        while let Some(tree) = queue.pop_front() {
            for sub_tree in tree.sub_trees.values() {
                queue.push_back(sub_tree);
            }
            let meta = tree.fs.metadata();
            let mut mp = inner.snapshot[&meta.fsid].1.as_str();
            if mp.is_empty() {
                mp = "/";
            }
            let (major, minor) = sep_dev(meta.dev);
            res += &format!(
                "{} {} {} {} {} {}\n",
                meta.source, mp, meta.fstype, tree.fs.flags(), major, minor,
            );
        }
        res
    }

    pub async fn lookup_absolute(
        &self,
        path: &str,
        follow_link: bool,
        token: AccessToken,
    ) -> SyscallResult<Arc<dyn Inode>> {
        assert!(is_absolute_path(path));
        let root = self.inner.lock().tree.fs.root();
        let inode = self.lookup_relative(root, &path[1..], follow_link, token).await?;
        Ok(inode)
    }

    pub async fn lookup_relative(
        &self,
        parent: Arc<dyn Inode>,
        path: &str,
        follow_link: bool,
        token: AccessToken,
    ) -> SyscallResult<Arc<dyn Inode>> {
        assert!(!is_absolute_path(&path));
        let mut names = split_path!(path).map(|s| s.to_string()).collect::<VecDeque<_>>();
        let mut inode = parent.clone();
        let mut linked = 0;
        loop {
            if inode.metadata().ifmt == InodeMode::S_IFLNK && (!names.is_empty() || follow_link) {
                let path = inode.clone().do_readlink().await?;
                debug!("[lookup] Follow link: {}", path);
                linked += 1;
                if linked > MAX_SYMLINKS {
                    return Err(Errno::ELOOP);
                }
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
                    inode = inode.lookup_name(&name, token).await?;
                }
            } else {
                break Ok(inode);
            }
        }
    }

    pub fn mount(
        &self,
        source: Option<&str>,
        target: Arc<dyn Inode>,
        fstype: &str,
        flags: VfsFlags,
    ) -> SyscallResult {
        if target.metadata().path.is_empty() { // Already mounted
            if flags.contains(VfsFlags::MS_REMOUNT) {
                target.file_system().upgrade().unwrap().remount(flags)?;
            } else {
                return Err(Errno::EEXIST);
            }
        } else {
            let parent = target.metadata().parent.clone().unwrap().upgrade().unwrap();
            let dir_name = target.metadata().name.clone();
            let absolute_path = target.mnt_ns_path(self)?;
            let mut inner = self.inner.lock();
            let fs: Arc<dyn FileSystem> = match fstype {
                "proc" => {
                    // TODO: Monitor 会不会存在竞争？
                    ProcFileSystem::new(flags, Some(parent.clone())).tap(|fs| {
                        inner.procfs = Arc::downgrade(fs);
                    })
                }
                "devtmpfs" => DevFileSystem::new(flags, Some(parent.clone())),
                "tmpfs" => TmpFileSystem::new(source, flags, Some(parent.clone())),
                _ => return Err(Errno::ENODEV),
            };
            let mnt_id = Self::do_mount(&mut inner.tree.sub_trees, fs.clone(), &absolute_path)?;
            inner.snapshot.insert(fs.metadata().fsid, (mnt_id, absolute_path.to_string()));
            parent.metadata().inner.lock().mounts.insert(dir_name, fs.root());
        }
        Ok(())
    }

    pub fn unmount(&self, target: Arc<dyn Inode>) -> SyscallResult {
        if !target.metadata().path.is_empty() {
            return Err(Errno::EINVAL);
        }
        let parent = target.metadata().parent.clone().unwrap().upgrade().unwrap();
        let absolute_path = target.mnt_ns_path(&self)?;
        let dir_name = absolute_path.rsplit_once('/').unwrap().1;
        let mut inner = self.inner.lock();
        let tree = Self::do_unmount(&mut inner.tree.sub_trees, &absolute_path)?;
        inner.snapshot.remove(&tree.fs.metadata().fsid);
        parent.metadata().inner.lock().mounts.remove(dir_name).unwrap();
        Ok(())
    }

    pub fn get_inode_snapshot(&self, inode: &dyn Inode) -> SyscallResult<(usize, String)> {
        let fsid = inode.file_system().upgrade().ok_or(Errno::EIO)?.metadata().fsid;
        let mp = self.inner.lock().snapshot.get(&fsid).cloned().expect("fsid not found");
        Ok(mp)
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
