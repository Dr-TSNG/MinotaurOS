use alloc::collections::LinkedList;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::fs::ffi::VfsFlags;
use crate::fs::inode::Inode;
use crate::result::{Errno, SyscallResult};
use crate::sync::mutex::Mutex;

pub enum FileSystemType {
    FAT32,
    TMPFS,
    PROCFS,
}

/// 文件系统
///
/// 一个文件系统在刚创建时不关联任何挂载点，通过 `move_mount` 挂载到命名空间。
pub struct FileSystem {
    /// 文件系统类型
    pub fstype: FileSystemType,

    /// 文件系统标志
    pub flags: VfsFlags,

    /// 挂载点
    ///
    /// 挂载点的引用生命周期与其本身相同
    pub mount_point: Mutex<Weak<MountPoint>>,

    /// 文件系统实现接口
    pub interface: Arc<dyn FileSystemImpl>,
}

impl FileSystem {
    pub fn new(fstype: FileSystemType, flags: VfsFlags, interface: Arc<dyn FileSystemImpl>) -> Self {
        Self {
            fstype,
            flags,
            mount_point: Mutex::default(),
            interface,
        }
    }
}

/// 文件系统实现接口
pub trait FileSystemImpl: Send + Sync {
    /// 根 Inode
    fn root(&self) -> SyscallResult<Arc<dyn Inode>>;
}

impl FileSystem {
    pub fn move_mount(this: Arc<Self>, target: Weak<MountNamespace>, path: &str) -> SyscallResult<MountPoint> {
        let lock = this.mount_point.lock();
        if let Some(old_mnt) = lock.upgrade() {
            if let Some(old_ns) = old_mnt.namespace.upgrade() {
                old_ns.unmount(old_mnt)?;
            }
        }
        drop(lock);
        let mnt = MountPoint {
            fs: this,
            namespace: target,
            mnt_id: MNT_ID_POOL.fetch_add(1, Ordering::Acquire),
            path: path.to_string(),
        };
        Ok(mnt)
    }
}

static MNT_ID_POOL: AtomicUsize = AtomicUsize::new(1);
static MNT_NS_ID_POOL: AtomicUsize = AtomicUsize::new(1);

/// 挂载点
///
/// 一个挂载点始终跟一个文件系统和挂载命名空间绑定。
pub struct MountPoint {
    pub fs: Arc<FileSystem>,
    pub namespace: Weak<MountNamespace>,
    pub mnt_id: usize,
    pub path: String,
}

/// 挂载命名空间
pub struct MountNamespace {
    pub mnt_ns_id: usize,
    pub inner: Mutex<MountNamespaceInner>,
}

pub struct MountNamespaceInner {
    /// 挂载链，暂时使用链式实现
    mount_link: LinkedList<Arc<MountPoint>>,
}

impl MountNamespace {
    pub fn new() -> Self {
        // mnt id 始终增加
        let mnt_ns_id = MNT_NS_ID_POOL.fetch_add(1, Ordering::Acquire);
        let inner = MountNamespaceInner {
            mount_link: LinkedList::new(),
        };
        Self {
            mnt_ns_id,
            inner: Mutex::new(inner),
        }
    }

    pub fn unmount(&self, mount_point: Arc<MountPoint>) -> SyscallResult {
        let mut lock = self.inner.lock();
        lock.mount_link
            .extract_if(|node| Arc::ptr_eq(node, &mount_point))
            .next()
            .ok_or(Errno::ENOENT)?;
        Ok(0)
    }
}
