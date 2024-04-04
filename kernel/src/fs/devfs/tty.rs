use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use async_trait::async_trait;
use lazy_static::lazy_static;
use crate::arch::sbi;
use crate::fs::file::{File, FileMeta};
use crate::result::{Errno, SyscallResult};
use crate::sched::yield_now;
use crate::sync::mutex::AsyncMutex;

pub struct TtyFile {
    metadata: FileMeta,
    mutex: AsyncMutex<()>,
}

lazy_static! {
    pub static ref TTY: Arc<TtyFile> = Arc::new(TtyFile::new());
}

impl TtyFile {
    fn new() -> Self {
        TtyFile {
            metadata: FileMeta {
                inode: None,
                prw_lock: Default::default(),
                inner: Default::default(),
            },
            mutex: AsyncMutex::new(()),
        }
    }
}

#[async_trait]
impl File for TtyFile {
    fn metadata(&self) -> &FileMeta {
        &self.metadata
    }

    async fn read(&self, buf: &mut [u8]) -> SyscallResult<isize> {
        let _lock = self.mutex.lock().await;
        loop {
            let size = sbi::console_read(buf).map_err(|_| Errno::EIO)?;
            match size {
                0 => yield_now().await,
                _ => return Ok(size as isize)
            }
        }
    }

    async fn write(&self, buf: &[u8]) -> SyscallResult<isize> {
        let _lock = self.mutex.lock().await;
        let str = String::from_utf8_lossy(buf);
        let size = sbi::console_write(&str).map_err(|_| Errno::EIO)?;
        Ok(size as isize)
    }
}
