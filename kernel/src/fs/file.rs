use alloc::sync::Arc;
use crate::fs::inode::Inode;
use crate::result::SyscallResult;
use crate::result::SyscallErrorCode::EINVAL;
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

pub trait File: Send + Sync {
    fn metadata(&self) -> &FileMeta;

    async fn read(&self, buf: &mut [u8]) -> SyscallResult;

    async fn write(&self, buf: &[u8]) -> SyscallResult;

    async fn pread(&self, buf: &mut [u8], offset: isize) -> SyscallResult {
        let _lock = self.metadata().rw_lock.lock().await;
        let old = self.seek(Seek::Cur(0))?;
        self.seek(Seek::Set(offset))?;
        let ret = self.read(buf).await;
        self.seek(Seek::Set(old))?;
        ret
    }

    async fn pwrite(&self, buf: &[u8], offset: isize) -> SyscallResult {
        let _lock = self.metadata().rw_lock.lock().await;
        let old = self.seek(Seek::Cur(0))?;
        self.seek(Seek::Set(offset))?;
        let ret = self.write(buf).await;
        self.seek(Seek::Set(old))?;
        ret
    }

    fn sync_read(&self, buf: &mut [u8]) -> SyscallResult {
        block_on(self.read(buf))
    }

    fn sync_write(&self, buf: &[u8]) -> SyscallResult {
        block_on(self.write(buf))
    }

    fn seek(&self, seek: Seek) -> SyscallResult {
        let metadata = self.metadata();
        let mut inner = metadata.inner.lock();
        inner.pos = match seek {
            Seek::Set(offset) => {
                if offset < 0 {
                    return Err(EINVAL);
                }
                offset
            }
            Seek::Cur(offset) => {
                #[allow(arithmetic_overflow)]
                    let new_pos = inner.pos + offset;
                if new_pos < 0 {
                    // TODO: EOVERFLOW
                    return Err(EINVAL);
                }
                new_pos
            }
            Seek::End(offset) => {
                let size = metadata.inode.metadata().inner.lock().size;
                #[allow(arithmetic_overflow)]
                    let new_pos = size + offset;
                if new_pos < 0 {
                    // TODO: EOVERFLOW
                    return Err(EINVAL);
                }
                new_pos
            }
        };
        Ok(inner.pos)
    }
}
