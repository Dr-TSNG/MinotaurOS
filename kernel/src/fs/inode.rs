use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicUsize, Ordering};
use async_trait::async_trait;
use downcast_rs::{DowncastSync, impl_downcast};
use crate::fs::ffi::{AccessMode, InodeMode, OpenFlags, VfsFlags};
use crate::fs::file::{CharacterFile, DirFile, File, FileMeta, RegularFile};
use crate::fs::file_system::{FileSystem, MountNamespace};
use crate::fs::page_cache::PageCache;
use crate::process::token::AccessToken;
use crate::process::{Gid, Uid};
use crate::process::ffi::CapSet;
use crate::result::{Errno, SyscallResult};
use crate::sched::ffi::TimeSpec;
use crate::sync::mutex::Mutex;

static KEY_COUNTER: AtomicUsize = AtomicUsize::new(1);

pub struct InodeMeta {
    pub key: usize,
    /// 结点编号
    pub ino: usize,
    /// 结点设备
    pub dev: u64,
    /// 结点类型
    pub ifmt: InodeMode,
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
    pub uid: Uid,
    /// gid
    pub gid: Gid,
    /// 访问权限
    pub mode: InodeMode,
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
    /// 是否已经被删除
    pub unlinked: bool,
    /// 挂载点
    pub mounts: BTreeMap<String, Arc<dyn Inode>>,
}

#[derive(Default)]
pub struct FCap {
    pub permitted: CapSet,
    pub inheritable: CapSet,
    pub effective: CapSet,
}

impl InodeMeta {
    /// 创建新的 Inode 元数据
    ///
    /// 若 `parent` 为 `None`，则指向自身
    pub fn new(
        ino: usize,
        dev: u64,
        uid: Uid,
        gid: Gid,
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
            uid,
            gid,
            mode,
            nlink: 1,
            atime,
            mtime,
            ctime,
            size,
            unlinked: false,
            mounts: BTreeMap::new(),
        };
        let key = KEY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let ifmt = mode & InodeMode::S_IFMT;
        let parent = parent.map(|parent| Arc::downgrade(&parent));
        Self { key, ino, dev, ifmt, name, path, parent, page_cache, inner: Arc::new(Mutex::new(inner)) }
    }

    pub fn new_simple(
        ino: usize,
        uid: Uid,
        gid: Gid,
        mode: InodeMode,
        name: String,
        parent: Arc<dyn Inode>,
    ) -> Self {
        let time = TimeSpec::default();
        let path = format!("{}/{}", parent.metadata().path, name);
        Self::new(ino, 0, uid, gid, mode, name, path, Some(parent), None, time, time, time, 0)
    }

    pub fn movein(
        inode: &dyn Inode,
        name: String,
        path: String,
        parent: Arc<dyn Inode>,
    ) -> Self {
        Self {
            key: inode.metadata().key,
            ino: inode.metadata().ino,
            dev: inode.metadata().dev,
            ifmt: inode.metadata().ifmt,
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
        token: AccessToken,
    ) -> SyscallResult<Arc<dyn Inode>> {
        Err(Errno::EPERM)
    }

    /// 在当前目录下创建符号链接
    async fn do_symlink(
        self: Arc<Self>,
        mode: InodeMode,
        name: &str,
        target: &str,
        token: AccessToken,
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

#[allow(private_bounds, unused)]
#[async_trait]
pub trait Inode: DowncastSync + InodeInternal {
    /// 获取 Inode 元数据
    fn metadata(&self) -> &InodeMeta;

    /// 获取文件系统
    fn file_system(&self) -> Weak<dyn FileSystem>;

    fn ioctl(
        &self,
        request: usize,
        value: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
    ) -> SyscallResult<i32> {
        Err(Errno::ENOTTY)
    }
}
impl_downcast!(sync Inode);

impl dyn Inode {
    pub fn open(self: Arc<Self>, flags: OpenFlags, token: AccessToken) -> SyscallResult<Arc<dyn File>> {
        if flags.contains(OpenFlags::O_RDWR) {
            self.proc_access(token, AccessMode::R_OK | AccessMode::W_OK)?;
        } else if flags.contains(OpenFlags::O_WRONLY) {
            self.proc_access(token, AccessMode::W_OK)?;
        } else if !flags.contains(OpenFlags::O_DIRECTORY) { // O_RDONLY
            self.proc_access(token, AccessMode::R_OK)?;
        }
        match self.metadata().ifmt {
            InodeMode::S_IFCHR => Ok(CharacterFile::new(FileMeta::new(Some(self), flags))),
            InodeMode::S_IFDIR => Ok(DirFile::new(FileMeta::new(Some(self), flags), token)),
            InodeMode::S_IFREG => Ok(RegularFile::new(FileMeta::new(Some(self), flags))),
            _ => Err(Errno::EPERM),
        }
    }

    pub fn page_cache(&self) -> Option<Arc<PageCache>> {
        self.metadata().page_cache.clone()
    }

    pub async fn read(&self, buf: &mut [u8], offset: isize) -> SyscallResult<isize> {
        match &self.metadata().page_cache {
            Some(cache) => cache.read(buf, offset).await,
            None => self.read_direct(buf, offset).await,
        }
    }

    pub async fn write(&self, buf: &[u8], offset: isize) -> SyscallResult<isize> {
        match &self.metadata().page_cache {
            Some(cache) => cache.write(buf, offset).await,
            None => self.write_direct(buf, offset).await,
        }
    }

    pub async fn truncate(&self, size: isize) -> SyscallResult {
        match &self.metadata().page_cache {
            Some(cache) => cache.truncate(size).await,
            None => self.truncate_direct(size).await,
        }
    }

    pub async fn sync(&self) -> SyscallResult<isize> {
        if let Some(page_cache) = &self.metadata().page_cache {
            page_cache.sync_all().await?;
        }
        Ok(0)
    }

    pub async fn lookup_name(self: Arc<Self>, name: &str, token: AccessToken) -> SyscallResult<Arc<dyn Inode>> {
        if self.metadata().inner.lock().unlinked {
            return Err(Errno::ENOENT);
        }
        if !self.metadata().ifmt.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        self.proc_access(token, AccessMode::X_OK)?;
        // 这里不能放到 match 里面，否则锁会被延后释放
        let inode = self.metadata().inner.lock().mounts.get(name).cloned();
        match inode {
            Some(inode) => Ok(inode),
            None => self.clone().do_lookup_name(name).await,
        }
    }

    pub async fn lookup_idx(self: Arc<Self>, idx: usize, token: AccessToken) -> SyscallResult<Arc<dyn Inode>> {
        if self.metadata().inner.lock().unlinked {
            return Err(Errno::ENOENT);
        }
        if !self.metadata().ifmt.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        self.proc_access(token, AccessMode::R_OK)?;
        self.clone().do_lookup_idx(idx).await.map(|inode| {
            let name = &self.metadata().name;
            self.metadata().inner.lock().mounts.get(name).cloned().unwrap_or(inode)
        })
    }

    pub async fn create(self: Arc<Self>, mode: InodeMode, name: &str, token: AccessToken) -> SyscallResult<Arc<dyn Inode>> {
        if self.metadata().inner.lock().unlinked {
            return Err(Errno::ENOENT);
        }
        if !self.metadata().ifmt.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        self.proc_access(token, AccessMode::W_OK)?;
        self.do_create(mode, name, token).await
    }

    pub async fn symlink(self: Arc<Self>, mode: InodeMode, name: &str, target: &str, token: AccessToken) -> SyscallResult {
        if self.metadata().inner.lock().unlinked {
            return Err(Errno::ENOENT);
        }
        if !self.metadata().ifmt.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        self.proc_access(token, AccessMode::W_OK)?;
        self.do_symlink(mode, name, target, token).await
    }

    pub async fn movein(self: Arc<Self>, name: &str, inode: Arc<dyn Inode>, token: AccessToken) -> SyscallResult {
        if self.metadata().inner.lock().unlinked {
            return Err(Errno::ENOENT);
        }
        if !self.metadata().ifmt.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        self.proc_access(token, AccessMode::W_OK)?;
        self.do_movein(name, inode).await
    }

    pub async fn unlink(self: Arc<Self>, name: &str, token: AccessToken) -> SyscallResult {
        if self.metadata().inner.lock().unlinked {
            return Err(Errno::ENOENT);
        }
        if self.metadata().inner.lock().mounts.get(name).is_some() {
            return Err(Errno::EBUSY);
        }
        self.proc_access(token, AccessMode::W_OK)?;
        let inode = self.clone().lookup_name(name, token).await?;
        inode.metadata().inner.lock().unlinked = true;
        if let Some(page_cache) = &inode.metadata().page_cache {
            page_cache.set_deleted();
        }
        self.do_unlink(inode).await
    }

    pub async fn readlink(self: Arc<Self>, token: AccessToken) -> SyscallResult<String> {
        if !self.metadata().ifmt.is_lnk() {
            return Err(Errno::EINVAL);
        }
        self.proc_access(token, AccessMode::R_OK)?;
        self.do_readlink().await
    }

    pub fn chmod(&self, mode: InodeMode, token: AccessToken) -> SyscallResult {
        let fs = self.file_system().upgrade().unwrap();
        if fs.flags().contains(VfsFlags::ST_RDONLY) {
            return Err(Errno::EROFS);
        }
        let mut inner = self.metadata().inner.lock();
        if token.uid != 0 && token.uid != inner.uid {
            return Err(Errno::EPERM);
        }
        inner.mode = inner.mode.difference(InodeMode::S_MISC) | mode;
        Ok(())
    }

    pub fn chown(&self, uid: Uid, gid: Gid, token: AccessToken) -> SyscallResult {
        let fs = self.file_system().upgrade().unwrap();
        if fs.flags().contains(VfsFlags::ST_RDONLY) {
            return Err(Errno::EROFS);
        }
        let mut inner = self.metadata().inner.lock();
        if token.uid != 0 && token.uid != inner.uid {
            return Err(Errno::EPERM);
        }
        if uid != Uid::MAX {
            inner.uid = uid;
        }
        if gid != Gid::MAX {
            inner.gid = gid;
        }
        if inner.mode & (InodeMode::S_IXUSR | InodeMode::S_IXGRP | InodeMode::S_IXOTH) != InodeMode::empty() {
            inner.mode -= InodeMode::S_ISUID;
            if token.uid != 0 || inner.mode.contains(InodeMode::S_IXGRP) {
                inner.mode -= InodeMode::S_ISGID;
            }
        }
        Ok(())
    }

    pub fn mnt_ns_path(&self, mnt_ns: &MountNamespace) -> SyscallResult<String> {
        let pre = mnt_ns.get_inode_snapshot(self)?.1;
        let mut path = format!("{}{}", pre, self.metadata().path);
        if path.is_empty() {
            path = "/".to_string();
        }
        Ok(path)
    }

    pub fn proc_access(&self, token: AccessToken, attempt: AccessMode) -> SyscallResult {
        let fs = self.file_system().upgrade().unwrap();
        let inner = self.metadata().inner.lock();
        let bypass_rw = token.uid == 0;
        let bypass_x = token.uid == 0 && self.metadata().ifmt.is_dir();
        let mode = if inner.uid == token.uid {
            AccessMode::new(
                bypass_rw | inner.mode.contains(InodeMode::S_IRUSR),
                bypass_rw | inner.mode.contains(InodeMode::S_IWUSR),
                bypass_x | inner.mode.contains(InodeMode::S_IXUSR),
            )
        } else if inner.gid == token.gid {
            AccessMode::new(
                bypass_rw | inner.mode.contains(InodeMode::S_IRGRP),
                bypass_rw | inner.mode.contains(InodeMode::S_IWGRP),
                bypass_x | inner.mode.contains(InodeMode::S_IXGRP),
            )
        } else {
            AccessMode::new(
                bypass_rw | inner.mode.contains(InodeMode::S_IROTH),
                bypass_rw | inner.mode.contains(InodeMode::S_IWOTH),
                bypass_x | inner.mode.contains(InodeMode::S_IXOTH),
            )
        };
        if attempt.contains(AccessMode::W_OK)
            && fs.flags().contains(VfsFlags::ST_RDONLY) {
            return Err(Errno::EROFS);
        }
        if attempt.contains(AccessMode::X_OK) && !self.metadata().ifmt.is_dir()
            && fs.flags().contains(VfsFlags::ST_NOEXEC) {
            return Err(Errno::EACCES);
        }
        if !mode.contains(attempt) {
            return Err(Errno::EACCES);
        }
        Ok(())
    }
}

pub struct DummyInode;

impl InodeInternal for DummyInode {}

impl Inode for DummyInode {
    fn metadata(&self) -> &InodeMeta {
        panic!()
    }

    fn file_system(&self) -> Weak<dyn FileSystem> {
        panic!()
    }
}
