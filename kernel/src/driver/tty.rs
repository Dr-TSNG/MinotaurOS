use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use async_trait::async_trait;
use crate::arch::sbi;
use crate::driver::{CharacterDevice, DeviceMeta};
use crate::fs::file::File;
use crate::result::{Errno, SyscallResult};
use crate::sched::yield_now;
use crate::sync::mutex::AsyncMutex;
use crate::sync::once::LateInit;

pub static DEFAULT_TTY: LateInit<Arc<dyn File>> = LateInit::new();

pub struct SBITtyDevice {
    metadata: DeviceMeta,
    mutex: AsyncMutex<()>,
}

impl SBITtyDevice {
    pub fn new() -> Self {
        Self {
            metadata: DeviceMeta::new("sbi_tty".to_string()),
            mutex: AsyncMutex::new(()),
        }
    }
}

#[async_trait]
impl CharacterDevice for SBITtyDevice {
    fn metadata(&self) -> &DeviceMeta {
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
