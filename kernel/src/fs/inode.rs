use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use core::any::Any;
use async_trait::async_trait;
use downcast_rs::{DowncastSync, impl_downcast};
use crate::fs::ffi::InodeMode;
use crate::fs::file::{CharacterFile, DirFile, File, FileMeta, RegularFile};
use crate::fs::file_system::FileSystem;
use crate::fs::page_cache::PageCache;
use crate::result::{Errno, SyscallResult};
use crate::sched::ffi::TimeSpec;
use crate::sync::mutex::{Mutex, MutexGuard};

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
    /// 是否加载了子目录
    pub children_loaded: bool,
    /// 子目录
    pub children: BTreeMap<String, InodeChild>,
    /// 挂载点
    pub mounts: BTreeMap<String, Arc<dyn Inode>>,
}

pub struct InodeChild {
    pub inode: Arc<dyn Inode>,
    pub ext: Box<dyn Any + Send + Sync>,
}

impl InodeChild {
    pub(crate) fn new(inode: Arc<dyn Inode>, ext: Box<dyn Any + Send + Sync>) -> Self {
        Self { inode, ext }
    }
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
            children_loaded: false,
            children: BTreeMap::new(),
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

    /// 加载子目录
    async fn load_children(
        self: Arc<Self>,
        inner: &mut InodeMetaInner,
    ) -> SyscallResult {
        Err(Errno::EPERM)
    }

    /// 在当前目录下创建文件/目录
    async fn do_create(
        self: Arc<Self>,
        mode: InodeMode,
        name: &str,
    ) -> SyscallResult<InodeChild> {
        Err(Errno::EPERM)
    }

    /// 将文件移动到当前目录下
    async fn do_movein(
        self: Arc<Self>,
        name: &str,
        inode: Arc<dyn Inode>,
    ) -> SyscallResult<InodeChild> {
        Err(Errno::EPERM)
    }

    /// 在当前目录下删除文件
    async fn do_unlink(
        self: Arc<Self>,
        target: &InodeChild,
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
}
impl_downcast!(sync Inode);

impl dyn Inode {
    pub fn open(self: Arc<Self>) -> SyscallResult<Arc<dyn File>> {
        match self.metadata().mode {
            InodeMode::IFCHR => Ok(CharacterFile::new(FileMeta::new(Some(self)))),
            InodeMode::IFDIR => Ok(DirFile::new(FileMeta::new(Some(self)))),
            InodeMode::IFREG => Ok(RegularFile::new(FileMeta::new(Some(self)))),
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
            page_cache.sync_all(self, false).await?;
        }
        Ok(0)
    }

    pub async fn list<'a>(self: &'a Arc<Self>, idx: usize) -> SyscallResult<ChildIter<'a>> {
        let mut inner = self.metadata().inner.lock();
        if !inner.children_loaded {
            self.clone().load_children(&mut inner).await?;
        }
        Ok(ChildIter { inode: self, inner, idx })
    }

    pub async fn lookup_name(self: Arc<Self>, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        if self.metadata().mode != InodeMode::IFDIR {
            return Err(Errno::ENOTDIR);
        }
        let mut inner = self.metadata().inner.lock();
        if !inner.children_loaded {
            self.clone().load_children(&mut inner).await?;
        }
        let mount = inner.mounts.get(name).map(Arc::clone);
        match mount {
            Some(inode) => Ok(inode),
            None => inner.children.get(name).map(|child| child.inode.clone()).ok_or(Errno::ENOENT),
        }
    }

    pub async fn lookup_idx(self: Arc<Self>, idx: usize) -> SyscallResult<Arc<dyn Inode>> {
        let mut inner = self.metadata().inner.lock();
        if !inner.children_loaded {
            self.clone().load_children(&mut inner).await?;
        }
        inner.children.values().nth(idx).map(|child| child.inode.clone()).ok_or(Errno::ENOENT)
    }

    pub async fn create(self: Arc<Self>, mode: InodeMode, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        let mut inner = self.metadata().inner.lock();
        if !inner.children_loaded {
            self.clone().load_children(&mut inner).await?;
        }
        if inner.children.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        let child = self.clone().do_create(mode, name).await?;
        let inode = child.inode.clone();
        inner.children.insert(name.to_string(), child);
        Ok(inode)
    }

    pub async fn movein(self: Arc<Self>, name: &str, inode: Arc<dyn Inode>) -> SyscallResult {
        let mut inner = self.metadata().inner.lock();
        if !inner.children_loaded {
            self.clone().load_children(&mut inner).await?;
        }
        if inner.children.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        let child = self.clone().do_movein(name, inode).await?;
        inner.children.insert(child.inode.metadata().name.clone(), child);
        Ok(())
    }

    pub async fn unlink(self: Arc<Self>, name: &str) -> SyscallResult<()> {
        let mut inner = self.metadata().inner.lock();
        if !inner.children_loaded {
            self.clone().load_children(&mut inner).await?;
        }
        let child = inner.children.get(name).ok_or(Errno::ENOENT)?;
        if let Some(page_cache) = &child.inode.metadata().page_cache {
            page_cache.set_deleted();
        }
        self.clone().do_unlink(child).await?;
        inner.children.remove(name);
        Ok(())
    }

    pub async fn readlink(self: Arc<Self>) -> SyscallResult<String> {
        if self.metadata().mode != InodeMode::IFLNK {
            return Err(Errno::EINVAL);
        }
        self.do_readlink().await
    }
}

pub struct ChildIter<'a> {
    inode: &'a Arc<dyn Inode>,
    inner: MutexGuard<'a, InodeMetaInner>,
    idx: usize,
}

impl Iterator for ChildIter<'_> {
    type Item = Arc<dyn Inode>;

    fn next(&mut self) -> Option<Self::Item> {
        let inode = match self.idx {
            0 => Some(self.inode.clone()),
            1 => Some(self.inode.metadata().parent.clone().and_then(|p| p.upgrade()).unwrap_or(self.inode.clone())),
            _ => self.inner.children.values().nth(self.idx - 2).map(|child| child.inode.clone()),
        };
        self.idx += 1;
        inode
    }
}
