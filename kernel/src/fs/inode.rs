use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use async_trait::async_trait;
use crate::fs::ffi::{OpenFlags, TimeSpec};
use crate::fs::file::File;
use crate::result::{Errno, SyscallResult};
use crate::sync::mutex::Mutex;

pub struct InodeMeta {
    /// 结点编号
    pub ino: usize,
    /// 结点设备
    pub dev: usize,
    /// 结点回环设备
    pub udev: usize,
    /// 可变数据
    pub inner: Mutex<InodeMetaInner>,
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
}


#[async_trait]
pub trait Inode: Send + Sync {
    /// 获取 Inode 元数据
    fn metadata(&self) -> &InodeMeta;

    /// 打开一个 Inode，返回打开的文件
    async fn open(&self) -> SyscallResult<Arc<dyn File>> {
        Err(Errno::EPERM)
    }
    
    /// 从 `offset` 处读取 `buf`
    async fn read(&self, buf: &mut [u8], offset: isize) -> SyscallResult {
        Err(Errno::EPERM)
    }

    /// 向 `offset` 处写入 `buf`
    async fn write(&self, buf: &[u8], offset: isize) -> SyscallResult {
        Err(Errno::EPERM)
    }

    /// 在当前目录下查找文件
    async fn lookup(&self, name: &str) -> SyscallResult<Arc<dyn Inode>> {
        Err(Errno::EPERM)
    }
    
    /// 列出目录下所有文件
    async fn list(&self) -> SyscallResult<Vec<Arc<dyn Inode>>> {
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

    /// 删除 Inode
    async fn unlink(&self) -> SyscallResult<Arc<dyn Inode>> {
        Err(Errno::EPERM)
    }
    
    /// 将 Inode 移动到新位置
    async fn moveto(&self, new_dir: Arc<dyn Inode>, new_name: &str) -> SyscallResult {
        Err(Errno::EPERM)
    }
    
    /// 同步修改
    async fn sync(&self) -> SyscallResult {
        Err(Errno::EPERM)
    }
}
