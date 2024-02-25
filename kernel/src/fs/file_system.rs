use alloc::boxed::Box;
use alloc::collections::LinkedList;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::fs::inode::Inode;
use crate::result::SyscallErrorCode::ENOENT;
use crate::result::SyscallResult;
use crate::sync::mutex::RwLock;

pub enum FileSystemType {
    FAT32,
    TMPFS,
    PROCFS,
}

#[derive(Clone)]
pub struct FileSystemMeta<'a> {
    /// 设备名
    pub dev_name: String,

    /// 文件系统类型
    pub fstype: FileSystemType,

    /// 挂载点
    ///
    /// 挂载点的引用生命周期与其本身相同
    pub mount_point: RwLock<Option<&'a MountPoint<'a>>>,

    /// 根 Inode
    pub root: Arc<dyn Inode>,
}

/// 文件系统
///
/// 一个文件系统在刚创建时不关联任何挂载点，通过 `move_mount` 挂载到命名空间。
pub trait FileSystem: Send + Sync {
    /// 获取文件系统元数据
    fn metadata(&self) -> &FileSystemMeta;
}

impl dyn FileSystem {
    pub fn move_mount(self, target: &MountNamespace, path: &str) -> SyscallResult<MountPoint> {
        let mut lock = self.metadata().mount_point.write();
        if let Some(old_mnt) = lock.take() {
            old_mnt.namespace.unmount(old_mnt)?;
        }
        let mnt = MountPoint {
            fs: Box::new(self),
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
pub struct MountPoint<'a> {
    pub fs: Box<dyn FileSystem>,
    pub namespace: &'a MountNamespace<'a>,
    pub mnt_id: usize,
    pub path: String,
}

/// 挂载命名空间
pub struct MountNamespace<'a> {
    pub mnt_ns_id: usize,
    pub inner: RwLock<MountNamespaceInner<'a>>,
}

pub struct MountNamespaceInner<'a> {
    /// 挂载链，暂时使用链式实现
    mount_link: LinkedList<MountPoint<'a>>,
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
            inner: RwLock::new(inner),
        }
    }

    pub fn unmount(&self, mount_point: &MountPoint) -> SyscallResult<Box<dyn FileSystem>> {
        let lock = self.inner.write();
        let mnt = lock.mount_link
            .extract_if(|node| Arc::ptr_eq(node, mount_point))
            .next()
            .ok_or(Err(ENOENT))?;
        Ok(mnt.fs)
    }
}
