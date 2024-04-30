use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use core::cmp::min;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use async_trait::async_trait;
use log::debug;
use crate::arch::VirtAddr;
use crate::fs::file::{File, FileMeta};
use crate::process::thread::event_bus::Event;
use crate::processor::{current_process, current_thread};
use crate::result::{Errno, SyscallResult};
use crate::sync::mutex::Mutex;
use crate::sync::once::LateInit;

pub struct Pipe {
    metadata: FileMeta,
    is_reader: bool,
    other: LateInit<Weak<Pipe>>,
    inner: Arc<Mutex<PipeInner>>,
}

#[derive(Default)]
struct PipeInner {
    buf: VecDeque<u8>,
    transfer: usize,
    readers: VecDeque<Waker>,
    writers: VecDeque<Waker>,
}

impl Drop for Pipe {
    fn drop(&mut self) {
        let mut inner = self.inner.lock();
        if self.is_reader {
            while let Some(waker) = inner.writers.pop_front() {
                waker.wake();
            }
        } else {
            while let Some(waker) = inner.readers.pop_front() {
                waker.wake();
            }
        }
    }
}

impl Pipe {
    pub fn new() -> (Arc<Self>, Arc<Self>) {
        let inner = Arc::new(Mutex::new(PipeInner::default()));
        let reader = Arc::new(Pipe {
            metadata: FileMeta::new(None),
            is_reader: true,
            other: LateInit::new(),
            inner: inner.clone(),
        });
        let writer = Arc::new(Pipe {
            metadata: FileMeta::new(None),
            is_reader: false,
            other: LateInit::new(),
            inner,
        });
        reader.other.init(Arc::downgrade(&writer));
        writer.other.init(Arc::downgrade(&reader));
        (reader, writer)
    }
}

#[async_trait]
impl File for Pipe {
    fn metadata(&self) -> &FileMeta {
        &self.metadata
    }

    async fn read(&self, buf: &mut [u8]) -> SyscallResult<isize> {
        if !self.is_reader {
            return Err(Errno::EBADF);
        }
        let fut = PipeReadFuture {
            pipe: self,
            user_buf: buf.as_ptr() as usize,
            pos: 0,
            len: buf.len(),
        };
        current_thread().event_bus.suspend_with(Event::KILL_PROCESS, fut).await
    }

    async fn write(&self, buf: &[u8]) -> SyscallResult<isize> {
        if self.is_reader {
            return Err(Errno::EBADF);
        }
        let fut = PipeWriteFuture {
            pipe: self,
            user_buf: buf.as_ptr() as usize,
            pos: 0,
            len: buf.len(),
            transfer: 0,
        };
        current_thread().event_bus.suspend_with(Event::KILL_PROCESS, fut).await
    }
}

struct PipeReadFuture<'a> {
    pipe: &'a Pipe,
    user_buf: usize,
    pos: usize,
    len: usize,
}

struct PipeWriteFuture<'a> {
    pipe: &'a Pipe,
    user_buf: usize,
    pos: usize,
    len: usize,
    transfer: usize,
}

impl Future for PipeReadFuture<'_> {
    type Output = SyscallResult<isize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut inner = self.pipe.inner.lock();
        let read = min(self.len - self.pos, inner.buf.len());
        debug!("[pipe] read poll pos: {}, len: {}, buf.len: {}, read: {}", self.pos, self.len, inner.buf.len(), read);
        if read > 0 {
            let user_buf = current_process().inner.lock().apply(|proc_inner| {
                proc_inner.addr_space.user_slice_w(VirtAddr(self.user_buf + self.pos), read)
            });
            match user_buf {
                Ok(user_buf) => {
                    for (i, b) in inner.buf.drain(..read).enumerate() {
                        user_buf[i] = b;
                    }
                    self.pos += read;
                    inner.transfer += read;
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
            while let Some(waker) = inner.writers.pop_front() {
                waker.wake();
            }
            Poll::Ready(Ok(read as isize))
        } else {
            if self.pipe.other.strong_count() == 0 {
                return Poll::Ready(Ok(0));
            }
            inner.readers.push_back(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl Future for PipeWriteFuture<'_> {
    type Output = SyscallResult<isize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut inner = self.pipe.inner.lock();
        let write = self.len - self.pos;
        debug!("[pipe] write poll pos: {}, len: {}, buf.len: {} write: {}", self.pos, self.len, inner.buf.len(), write);
        if write == 0 && inner.transfer >= self.transfer {
            return Poll::Ready(Ok(self.len as isize));
        }
        if self.pipe.other.strong_count() == 0 {
            return Poll::Ready(Err(Errno::EPIPE));
        }
        if write > 0 {
            let user_buf = current_process().inner.lock().apply(|proc_inner| {
                proc_inner.addr_space.user_slice_r(VirtAddr(self.user_buf + self.pos), write)
            });
            match user_buf {
                Ok(user_buf) => {
                    inner.buf.extend(user_buf);
                    self.pos += write;
                    self.transfer = inner.transfer + write;
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
            while let Some(waker) = inner.readers.pop_front() {
                waker.wake();
            }
        }
        inner.writers.push_back(cx.waker().clone());
        Poll::Pending
    }
}
