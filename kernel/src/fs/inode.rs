use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use async_trait::async_trait;
use downcast_rs::{DowncastSync, impl_downcast};
use crate::fs::ffi::{InodeMode, OpenFlags};
use crate::fs::file::{CharacterFile, DirFile, File, FileMeta, RegularFile};
use crate::fs::file_system::FileSystem;
use crate::fs::page_cache::PageCache;
use crate::result::{Errno, SyscallResult};
use crate::sched::ffi::TimeSpec;
use crate::sync::mutex::Mutex;

pub struct InodeMeta {
    /// 结点编号
    pub ino: usize,
    /// 结点设备
    pub dev: usize,
    /// 结点类型
    pub mode: InodeMode,
    /// 文件名
    pub name: String,
    /// 文件系统路径
    pub path: String,
    /// 父目录
    pub parent: Option<Weak<dyn Inode>>,
    /// 页面缓存
    pub page_cache: Option<Arc<PageCache>>,
    /// 可变数据
    pub inner: Arc<Mutex<InodeMetaInner>>,
}

pub struct InodeMetaInner {
    /// uid
    pub uid: usize,
    /// gid
    pub gid: usize,
    /// 硬链接数
    pub nlink: usize,
    /// 访问时间
    pub atime: TimeSpec,
    /// 修改时间
    pub mtime: TimeSpec,
    /// 创建时间
    pub ctime: TimeSpec,
    /// 文件大小
    pub size: isize,
    /// 挂载点
    pub mounts: BTreeMap<String, Arc<dyn Inode>>,
}

impl InodeMeta {
    /// 创建新的 Inode 元数据
    ///
    /// 若 `parent` 为 `None`，则指向自身
    pub fn new(
        ino: usize,
        dev: usize,
        mode: InodeMode,
        name: String,
        path: String,
        parent: Option<Arc<dyn Inode>>,
        page_cache: Option<Arc<PageCache>>,
        atime: TimeSpec,
        mtime: TimeSpec,
        ctime: TimeSpec,
        size: isize,
    ) -> Self {
        let inner = InodeMetaInner {
            uid: 0,
            gid: 0,
            nlink: 1,
            atime,
            mtime,
            ctime,
            size,
            mounts: BTreeMap::new(),
        };
        let parent = parent.map(|parent| Arc::downgrade(&parent));
        Self { ino, dev, mode, name, path, parent, page_cache, inner: Arc::new(Mutex::new(inner)) }
    }

    pub fn movein(
        inode: &dyn Inode,
        name: String,
        path: String,
        parent: Arc<dyn Inode>,
    ) -> Self {
        Self {
            ino: inode.metadata().ino,
            dev: inode.metadata().dev,
            mode: inode.metadata().mode,
            name,
            path,
            parent: Some(Arc::downgrade(&parent)),
            page_cache: inode.page_cache().clone(),
            inner: inode.metadata().inner.clone(),
        }
    }
}

#[allow(unused)]
#[async_trait]
pub(super) trait InodeInternal {
    /// 从 `offset` 处读取 `buf`，绕过缓存
    async fn read_direct(&self, buf: &mut [u8], offset: isize) -> SyscallResult<isize> {
        Err(Errno::EPERM)
    }

    /// 向 `offset` 处写入 `buf`，绕过缓存
    async fn write_direct(&self, buf: &[u8], offset: isize) -> SyscallResult<isize> {
        Err(Errno::EPERM)
    }

    /// 设置文件大小，绕过缓存
    async fn truncate_direct(&self, size: isize) -> SyscallResult {
        Err(Errno::EPERM)
    }

    /// 查询目录项
    async fn do_lookup_name(
        self: Arc<Self>,
        name: &str,
    ) -> SyscallResult<Arc<dyn Inode>> {
        Err(Errno::EPERM)
    }

    /// 查询目录项
    async fn do_lookup_idx(
        self: Arc<Self>,
        idx: usize,
    ) -> SyscallResult<Arc<dyn Inode>> {
        Err(Errno::EPERM)
    }

    /// 在当前目录下创建文件/目录
    async fn do_create(
        self: Arc<Self>,
        mode: InodeMode,
        name: &str,
    ) -> SyscallResult<Arc<dyn Inode>> {
        Err(Errno::EPERM)
    }

    /// 在当前目录下创建符号链接
    async fn do_symlink(
        self: Arc<Self>,
        name: &str,
        target: &str,
    ) -> SyscallResult {
        Err(Errno::EPERM)
    }

    /// 将文件移动到当前目录下
    async fn do_movein(
        self: Arc<Self>,
        name: &str,
        inode: Arc<dyn Inode>,
    ) -> SyscallResult {
        Err(Errno::EPERM)
    }

    /// 在当前目录下删除文件
    async fn do_unlink(
        self: Arc<Self>,
        target: Arc<dyn Inode>,
    ) -> SyscallResult {
        Err(Errno::EPERM)
    }

    /// 读取符号链接
    async fn do_readlink(self: Arc<Self>) -> SyscallResult<String> {
        Err(Errno::EPERM)
    }
}

#[allow(private_bounds)]
#[async_trait]
pub trait Inode: DowncastSync + InodeInternal {
    /// 获取 Inode 元数据
    fn metadata(&self) -> &InodeMeta;

    /// 获取文件系统
    fn file_system(&self) -> Weak<dyn FileSystem>;

    fn ioctl(&self, request: usize, value: usize, arg3: usize, arg4: usize, arg5: usize) -> SyscallResult<i32>;
}
impl_downcast!(sync Inode);

impl dyn Inode {
    pub fn open(self: Arc<Self>, flags: OpenFlags) -> SyscallResult<Arc<dyn File>> {
        match self.metadata().mode {
            InodeMode::IFCHR => Ok(CharacterFile::new(FileMeta::new(Some(self), flags))),
            InodeMode::IFDIR => Ok(DirFile::new(FileMeta::new(Some(self), flags))),
            InodeMode::IFREG => Ok(RegularFile::new(FileMeta::new(Some(self), flags))),
            _ => Err(Errno::EPERM),
        }
    }

    pub fn page_cache(&self) -> Option<Arc<PageCache>> {
        self.metadata().page_cache.clone()
    }

    pub async fn read(&self, buf: &mut [u8], offset: isize) -> SyscallResult<isize> {
        match &self.metadata().page_cache {
            Some(cache) => cache.read(self, buf, offset).await,
            None => self.read_direct(buf, offset).await,
        }
    }

    pub async fn write(&self, buf: &[u8], offset: isize) -> SyscallResult<isize> {
        match &self.metadata().page_cache {
            Some(cache) => cache.write(self, buf, offset).await,
            None => self.write_direct(buf, offset).await,
        }
    }

    pub async fn truncate(&self, size: isize) -> SyscallResult {
        match &self.metadata().page_cache {
            Some(cache) => cache.truncate(self, size).await,
            None => self.truncate_direct(size).await,
        }
    }

    pub async fn sync(&self) -> SyscallResult<isize> {
        if let Some(page_cache) = &self.metadata().page_cache {
            page_cache.sync_all(self).await?;
        }
        Ok(0)
    }

    pub async fn lookup_name(self: Arc<Self>, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        if self.metadata().mode != InodeMode::IFDIR {
            return Err(Errno::ENOTDIR);
        }
        // 这里不能放到 match 里面，否则锁会被延后释放
        let inode = self.metadata().inner.lock().mounts.get(name).cloned();
        match inode {
            Some(inode) => Ok(inode),
            None => self.clone().do_lookup_name(name).await,
        }
    }

    pub async fn lookup_idx(self: Arc<Self>, idx: usize) -> SyscallResult<Arc<dyn Inode>> {
        if self.metadata().mode != InodeMode::IFDIR {
            return Err(Errno::ENOTDIR);
        }
        self.clone().do_lookup_idx(idx).await.map(|inode| {
            let name = &self.metadata().name;
            self.metadata().inner.lock().mounts.get(name).cloned().unwrap_or(inode)
        })
    }

    pub async fn create(self: Arc<Self>, mode: InodeMode, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        if self.metadata().mode != InodeMode::IFDIR {
            return Err(Errno::ENOTDIR);
        }
        self.do_create(mode, name).await
    }

    pub async fn symlink(self: Arc<Self>, name: &str, target: &str) -> SyscallResult {
        if self.metadata().mode != InodeMode::IFDIR {
            return Err(Errno::ENOTDIR);
        }
        self.do_symlink(name, target).await
    }

    pub async fn movein(self: Arc<Self>, name: &str, inode: Arc<dyn Inode>) -> SyscallResult {
        if self.metadata().mode != InodeMode::IFDIR {
            return Err(Errno::ENOTDIR);
        }
        self.do_movein(name, inode).await
    }

    pub async fn unlink(self: Arc<Self>, name: &str) -> SyscallResult {
        if self.metadata().inner.lock().mounts.get(name).is_some() {
            return Err(Errno::EBUSY);
        }
        let inode = self.clone().lookup_name(name).await?;
        if let Some(page_cache) = &inode.metadata().page_cache {
            page_cache.set_deleted();
        }
        self.do_unlink(inode).await
    }

    pub async fn readlink(self: Arc<Self>) -> SyscallResult<String> {
        if self.metadata().mode != InodeMode::IFLNK {
            return Err(Errno::EINVAL);
        }
        self.do_readlink().await
    }
}
