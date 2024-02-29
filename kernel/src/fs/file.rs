use alloc::boxed::Box;
use alloc::sync::Arc;
use async_trait::async_trait;
use crate::fs::inode::Inode;
use crate::result::{Errno, SyscallResult};
use crate::sync::block_on;
use crate::sync::mutex::{AsyncMutex, Mutex};

pub struct FileMeta {
    pub inode: Arc<dyn Inode>,
    pub rw_lock: AsyncMutex<()>,
    pub inner: Mutex<FileMetaInner>,
}

pub struct FileMetaInner {
    pub pos: isize,
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
        let _lock = self.metadata().rw_lock.lock().await;
        let old = self.seek(Seek::Cur(0))?;
        self.seek(Seek::Set(offset))?;
        let ret = self.read(buf).await;
        self.seek(Seek::Set(old))?;
        ret
    }

    async fn pwrite(&self, buf: &[u8], offset: isize) -> SyscallResult<isize> {
        let _lock = self.metadata().rw_lock.lock().await;
        let old = self.seek(Seek::Cur(0))?;
        self.seek(Seek::Set(offset))?;
        let ret = self.write(buf).await;
        self.seek(Seek::Set(old))?;
        ret
    }

    fn sync_read(&self, buf: &mut [u8]) -> SyscallResult<isize> {
        block_on(self.read(buf))
    }

    fn sync_write(&self, buf: &[u8]) -> SyscallResult<isize> {
        block_on(self.write(buf))
    }

    fn seek(&self, seek: Seek) -> SyscallResult<isize> {
        let metadata = self.metadata();
        let mut inner = metadata.inner.lock();
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
