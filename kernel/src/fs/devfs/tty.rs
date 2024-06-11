use crate::driver::CharacterDevice;
use crate::fs::file::{File, FileMeta};
use crate::result::{Errno, SyscallResult};
use crate::sync::once::LateInit;
use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use async_trait::async_trait;
use core::task::Waker;

pub static DEFAULT_TTY: LateInit<Arc<dyn File>> = LateInit::new();

pub struct TtyFile {
    metadata: FileMeta,
    device: Weak<dyn CharacterDevice>,
}

impl TtyFile {
    pub fn new(metadata: FileMeta, device: Arc<dyn CharacterDevice>) -> Arc<Self> {
        Arc::new(Self {
            metadata,
            device: Arc::downgrade(&device),
        })
    }
}

#[async_trait]
impl File for TtyFile {
    fn metadata(&self) -> &FileMeta {
        &self.metadata
    }

    async fn read(&self, buf: &mut [u8]) -> SyscallResult<isize> {
        let device = self.device.upgrade().ok_or(Errno::ENODEV)?;
        for i in 0..buf.len() {
            buf[i] = device.getchar().await?;
        }
        Ok(buf.len() as isize)
    }

    async fn write(&self, buf: &[u8]) -> SyscallResult<isize> {
        let device = self.device.upgrade().ok_or(Errno::ENODEV)?;
        for ch in buf.iter() {
            device.putchar(*ch).await?;
        }
        Ok(buf.len() as isize)
    }

    async fn ioctl(
        &self,
        request: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
    ) -> SyscallResult<i32> {
        // TODO: Real ioctl
        Ok(0)
    }

    fn pollin(&self, waker: Option<Waker>) -> SyscallResult<bool> {
        let device = self.device.upgrade().ok_or(Errno::ENODEV)?;
        if device.has_data() {
            Ok(true)
        } else {
            if let Some(waker) = waker {
                device.register_waker(waker);
            }
            Ok(false)
        }
    }
}
