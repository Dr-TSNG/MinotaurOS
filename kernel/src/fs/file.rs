use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use async_trait::async_trait;
use crate::arch::PAGE_SIZE;
use crate::fs::inode::Inode;
use crate::mm::region::ASRegion;
use crate::result::{Errno, SyscallResult};
use crate::sync::mutex::AsyncMutex;

pub struct FileMeta {
    pub inode: Arc<dyn Inode>,
    pub prw_lock: AsyncMutex<()>,
    pub inner: AsyncMutex<FileMetaInner>,
}

#[derive(Default)]
pub struct FileMetaInner {
    /// 位置指针
    pub pos: isize,
    /// 页缓存
    pub page_cache: BTreeMap<usize, Weak<Box<dyn ASRegion>>>,
}

impl FileMeta {
    pub fn new(inode: Arc<dyn Inode>) -> Self {
        FileMeta {
            inode,
            prw_lock: AsyncMutex::default(),
            inner: AsyncMutex::default(),
        }
    }
}

/// https://man7.org/linux/man-pages/man2/lseek.2.html
pub enum Seek {
    /// The file offset is set to offset bytes.
    Set(isize),
    /// The file offset is set to its current location plus `offset` bytes.
    Cur(isize),
    /// The file offset is set to the size of the file plus `offset` bytes.
    End(isize),
}

#[async_trait]
pub trait File: Send + Sync {
    fn metadata(&self) -> &FileMeta;

    async fn read(&self, buf: &mut [u8]) -> SyscallResult<isize>;

    async fn write(&self, buf: &[u8]) -> SyscallResult<isize>;

    async fn pread(&self, buf: &mut [u8], offset: isize) -> SyscallResult<isize> {
        let _lock = self.metadata().prw_lock.lock().await;
        let old = self.seek(Seek::Cur(0)).await?;
        self.seek(Seek::Set(offset)).await?;
        let ret = self.read(buf).await;
        self.seek(Seek::Set(old)).await?;
        ret
    }

    async fn pwrite(&self, buf: &[u8], offset: isize) -> SyscallResult<isize> {
        let _lock = self.metadata().prw_lock.lock().await;
        let old = self.seek(Seek::Cur(0)).await?;
        self.seek(Seek::Set(offset)).await?;
        let ret = self.write(buf).await;
        self.seek(Seek::Set(old)).await?;
        ret
    }

    async fn read_all(&self) -> SyscallResult<Vec<u8>> {
        self.seek(Seek::Set(0)).await?;
        let mut buf = Vec::new();
        let mut tmp = [0u8; PAGE_SIZE];
        loop {
            let len = self.read(&mut tmp).await?;
            if len == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..len as usize]);
        }
        Ok(buf)
    }

    async fn seek(&self, seek: Seek) -> SyscallResult<isize> {
        let metadata = self.metadata();
        let mut inner = metadata.inner.lock().await;
        inner.pos = match seek {
            Seek::Set(offset) => {
                if offset < 0 {
                    return Err(Errno::EINVAL);
                }
                offset
            }
            Seek::Cur(offset) => {
                match inner.pos.checked_add(offset) {
                    Some(new_pos) => new_pos,
                    None => return Err(if offset < 0 { Errno::EINVAL } else { Errno::EOVERFLOW }),
                }
            }
            Seek::End(offset) => {
                let size = metadata.inode.metadata().inner.lock().size;
                match size.checked_add(offset) {
                    Some(new_pos) => new_pos,
                    None => return Err(if offset < 0 { Errno::EINVAL } else { Errno::EOVERFLOW }),
                }
            }
        };
        Ok(inner.pos)
    }
}

pub struct RegularFile {
    metadata: FileMeta,
}

impl RegularFile {
    pub fn new(metadata: FileMeta) -> Self {
        Self { metadata }
    }
}

#[async_trait]
impl File for RegularFile {
    fn metadata(&self) -> &FileMeta {
        &self.metadata
    }

    // TODO: Page Cache
    async fn read(&self, buf: &mut [u8]) -> SyscallResult<isize> {
        let inode = self.metadata.inode.clone();
        let mut inner = self.metadata.inner.lock().await;
        let count = inode.read(buf, inner.pos).await?;
        inner.pos += count;
        Ok(count)
    }

    async fn write(&self, buf: &[u8]) -> SyscallResult<isize> {
        let inode = self.metadata.inode.clone();
        let mut inner = self.metadata.inner.lock().await;
        let count = inode.write(buf, inner.pos).await?;
        inner.pos += count;
        Ok(count)
    }
}
