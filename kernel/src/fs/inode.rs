use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use async_trait::async_trait;
use crate::fs::ffi::{InodeMode, OpenFlags, TimeSpec};
use crate::fs::file::File;
use crate::result::{Errno, SyscallResult};
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
    /// 可变数据
    pub inner: Mutex<InodeMetaInner>,
}

#[derive(Default)]
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
    /// 父目录
    pub parent: Option<Weak<dyn Inode>>,
    /// 挂载点
    pub mounts: BTreeMap<String, Arc<dyn Inode>>,
}

impl InodeMeta {
    pub fn new(
        ino: usize,
        dev: usize,
        mode: InodeMode,
        name: String,
        path: String,
        atime: TimeSpec,
        mtime: TimeSpec,
        ctime: TimeSpec,
        size: isize,
        parent: Option<Weak<dyn Inode>>,
    ) -> Self {
        Self {
            ino,
            dev,
            mode,
            name,
            path,
            inner: Mutex::new(InodeMetaInner {
                uid: 0,
                gid: 0,
                nlink: 1,
                atime,
                mtime,
                ctime,
                size,
                parent,
                mounts: BTreeMap::new(),
            }),
        }
    }
}

#[async_trait]
pub trait Inode: Send + Sync {
    /// 获取 Inode 元数据
    fn metadata(&self) -> &InodeMeta;

    /// 打开一个 Inode，返回打开的文件
    async fn open(self: Arc<Self>) -> SyscallResult<Arc<dyn File>> {
        Err(Errno::EPERM)
    }

    /// 从 `offset` 处读取 `buf`
    async fn read(&self, buf: &mut [u8], offset: isize) -> SyscallResult<isize> {
        Err(Errno::EPERM)
    }

    /// 向 `offset` 处写入 `buf`
    async fn write(&self, buf: &[u8], offset: isize) -> SyscallResult<isize> {
        Err(Errno::EPERM)
    }

    /// 在当前目录下查找文件
    async fn lookup(self: Arc<Self>, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        Err(Errno::EPERM)
    }

    /// 列出目录下编号 `iter` 的文件
    async fn list(self: Arc<Self>, iter: usize) -> SyscallResult<Arc<dyn Inode>> {
        Err(Errno::EPERM)
    }

    /// 在当前目录下创建文件
    async fn create(&self, name: &str, mode: OpenFlags) -> SyscallResult<Arc<dyn Inode>> {
        Err(Errno::EPERM)
    }

    /// 在当前目录下创建目录
    async fn mkdir(&self, name: &str, mode: OpenFlags) -> SyscallResult<Arc<dyn Inode>> {
        Err(Errno::EPERM)
    }

    /// 在当前目录下删除文件
    async fn unlink(&self, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        Err(Errno::EPERM)
    }

    /// 同步修改
    async fn sync(&self) -> SyscallResult {
        Err(Errno::EPERM)
    }
}
